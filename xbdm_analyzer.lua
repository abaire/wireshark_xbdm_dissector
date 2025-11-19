--[[
 * xbdm_analyzer.lua
 * wireshark plugin to process Xbox debug manager (XBDM) communication.
 *]]


set_plugin_info({ version = "0.1", author = "Erik Abair", description = "Postdissector to follow an XDBM conversation with a Microsoft Xbox." })

-- Input fields
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")
local tcp_srcport_field = Field.new("tcp.srcport")
local tcp_dstport_field = Field.new("tcp.dstport")
local tcp_stream_field = Field.new("tcp.stream")
local tcp_retransmission_field = Field.new('tcp.analysis.retransmission')

-- Output fields
local sender_field = ProtoField.string("xbdm.sender", "Sender")

local request_field = ProtoField.new("Request", "xbdm.request", ftypes.STRING, frametype.REQUEST)
local command_field = ProtoField.string("xbdm.command", "Command")
local raw_request_field = ProtoField.bytes("xbdm.binary_request_bytes", "Data")
local notifyat_port_field = ProtoField.uint16("xbdm.command.notifyat.port", "Requested notification port")
local binary_send_start_field = ProtoField.framenum("xbdm.binary_send_start", "Send start")
local binary_send_end_field = ProtoField.framenum("xbdm.binary_send_end", "Send end")

local request_packet_field = ProtoField.framenum("xbdm.request_packet", "Command packet")
local response_field = ProtoField.new("Response", "xbdm.response", ftypes.STRING, frametype.RESPONSE)
local raw_response_field = ProtoField.bytes("xbdm.binary_response_bytes", "Data")
local multiline_response_start_field = ProtoField.framenum("xbdm.multiline_response_start", "Response start")
local multiline_response_end_field = ProtoField.framenum("xbdm.multiline_response_end", "Response end")
local binary_response_start_field = ProtoField.framenum("xbdm.binary_response_start", "Response start")
local binary_response_end_field = ProtoField.framenum("xbdm.binary_response_end", "Response end")

local is_binary_field = ProtoField.bool("xbdm.is_binary", "Binary payload")

local xbdm_dissector = Proto("XBDM", "Xbox debug manager dissector")

xbdm_dissector.fields = {
    sender_field,
    request_field,
    command_field,
    raw_request_field,
    notifyat_port_field,
    binary_send_start_field,
    binary_send_end_field,
    request_packet_field,
    response_field,
    raw_response_field,
    multiline_response_start_field,
    multiline_response_end_field,
    binary_response_start_field,
    binary_response_end_field,
    is_binary_field,
}

local notification_sender_field = ProtoField.string("xbdm.notification.sender", "Sender")
local notification_command_field = ProtoField.string("xbdm.notification.command", "Command")
local notification_debug_message_field = ProtoField.string("xbdm.notification.debug", "Debug message")

local xbdm_notification_dissector = Proto("XBDM-Notification", "Xbox debug manager notification dissector")
xbdm_notification_dissector.fields = {
    notification_sender_field,
    notification_command_field,
    notification_debug_message_field,
}


-- Search a tvb for a \r\n pair.
local function find_end_of_request(tvb, offset)
    offset = offset or 0
    local max_len = math.min(512, tvb:len() - offset)

    local search_range = tvb:range(offset, max_len)
    local data = search_range:string()

    local crlf_offset = string.find(data, "\r\n")

    if crlf_offset then
        return offset + crlf_offset - 1
    else
        return nil
    end
end

-- Search a tvb for a \r\n.\r\n embedded multiline end token.
local function find_end_of_embedded_multiline(tvb, offset)
    offset = offset or 0
    local max_len = math.min(1024, tvb:len() - offset)

    local search_range = tvb:range(offset, max_len)
    local data = search_range:string()

    local end_offset = string.find(data, "\r\n.\r\n")

    if end_offset then
        return offset + end_offset - 1
    else
        return nil
    end
end


-- Returns a string containing the XBDM command in the given buffer or nil.
local function extract_request(tvb, offset)
    return tvb:range(offset or 0, find_end_of_request(tvb, offset)):string()
end

local function extract_first_word(command_string)
    local _, _, word = string.find(command_string, "^([^%s]+)")
    return word
end

-- Attempts to match up a response packet with its request.
local function find_closest_previous_or_same_packet(search_table, packet_number)
    local exact_match = search_table[packet_number]
    if exact_match ~= nil then
        return packet_number, exact_match
    end

    local closest_key
    local closest_value
    local closest_diff = math.huge
    for key, value in pairs(search_table) do
        if key < packet_number then
            local diff = packet_number - key
            if diff < closest_diff then
                closest_diff = diff
                closest_key = key
                closest_value = value
            end
        end
    end

    return closest_key, closest_value
end

local function starts_with(str, prefix)
    local substring = string.sub(str, 1, #prefix)
    return string.lower(substring) == prefix
end


-- Holds information about a single Xbox <-> computer notification conversation.
local NotificationConversationContext = {}

function NotificationConversationContext.new(tcp_stream)
    local ret = {
        -- The wireshark TCP stream that this conversation is associated with.
        tcp_stream_id = tcp_stream,
    }
    -- Processes the given buffer as a request from the computer -> Xbox.
    function ret:process_notification(xbdm_data, tvb, pinfo)
        local notification = extract_request(tvb)
        if not pinfo.visited then
            self:first_time_process_request_packet(notification, tvb, pinfo)
        end

        xbdm_data:add(notification_command_field, notification)

        if starts_with(notification, "debugstr ") then
            local debug_message = string.sub(notification, 10)
            xbdm_data:add(notification_debug_message_field, debug_message)
            pinfo.cols.info:set("DBG:" .. debug_message)
        else
            pinfo.cols.info:set(notification)
        end
    end

    return ret
end


-- Ports which are expected to receive push data from the Xbox
local known_notification_ports = {}

local function parse_size_param(command, size_parameter_name)
    command = string.lower(command)
    local _, _, value = string.find(command, size_parameter_name .. "=(0x%x+)")
    if value == nil then
        _, _, value = string.find(command, size_parameter_name .. "=(%d+)")
    end

    if value == nil then
        return nil
    end

    return tonumber(value)
end

local function register_notification_conversation(command)
    -- notifyat port=1234
    -- notifyat Port=0xff7d drop debug
    local port_section = parse_size_param(command, "port")
    if port_section == nil then
        print("Error: Missing port")
        return nil
    end

    local port = tonumber(port_section)
    known_notification_ports[port] = true
    DissectorTable.get("tcp.port"):add(port, xbdm_notification_dissector)

    -- TODO: Unregister anytime the stream is closed.

    return port
end

-- Holds information about a single computer <-> Xbox conversation.
local ConversationContext = {}

function ConversationContext.new(tcp_stream)
    local ret = {
        -- The wireshark TCP stream that this conversation is associated with.
        tcp_stream_id = tcp_stream,

        -- Maps a computer -> Xbox packet number to its XBDM command as a string.
        packet_to_request = {},

        -- Maps Xbox -> computer packet numbers to the packet number that initiated a multiline response (terminated with ".\r\n").
        multiline_response_packets = {},
        -- Map of the packet ID that starts a multiline response to the packet that contains the terminator.
        multiline_response_end_packets = {},

        -- Maps Xbox -> computer packet numbers to the packet number that initiated a binary response.
        binary_response_packets = {},
        -- Map of the packet ID that starts a binary response to the packet that contains the last byte.
        binary_response_end_packets = {},

        -- set of packet IDs that are part of a binary send. Each entry will be a pair of packet ID containing the command that
        -- initiated the send and an integer indicating how many bytes remain after the packet.
        binary_send_packets = {},
        -- Map of the packet ID that starts a multi-packet binary stream to the packet that contains the last byte.
        binary_send_stream_end_packets = {},

        -- Maps packet IDs that register notification ports to the decimal port they register.
        notification_registration_packets = {},
    }

    -- Processes the given buffer as a request from the computer -> Xbox.
    function ret:process_request(xbdm_data, tvb, pinfo)
        local command = extract_request(tvb)
        if not pinfo.visited then
            self:first_time_process_request_packet(command, tvb, pinfo)
        end

        local command_field_value = self:connect_send_chain(xbdm_data, command, pinfo)
        if command_field_value then
            xbdm_data:add(request_field, command_field_value)
            xbdm_data:add(command_field, string.lower(extract_first_word(command_field_value)))
            pinfo.cols.info:set(command_field_value)
        else
            xbdm_data:add(is_binary_field, true)
            xbdm_data:add(raw_request_field, tvb(0, tvb:captured_len()))
            pinfo.cols.info:set("<DATA>")
        end

        local notification_port = self.notification_registration_packets[pinfo.number]
        if notification_port ~= nil then
            xbdm_data:add(notifyat_port_field, notification_port)
        end
    end

    -- Processes the given buffer as a response from the Xbox -> computer.
    function ret:process_response(xbdm_data, tvb, pinfo)
        local response = extract_request(tvb)
        local command_number, command = find_closest_previous_or_same_packet(self.packet_to_request, pinfo.number)
        if command then
            xbdm_data:add(request_field, command)
            xbdm_data:add(command_field, string.lower(extract_first_word(command)))
        else
            xbdm_data:add(request_field, "UNKNOWN")
        end
        if command_number ~= nul then
            xbdm_data:add(request_packet_field, command_number)
        end

        if not pinfo.visited then
            self:first_time_process_response_packet(command_number, command, response, tvb, pinfo)
        end

        local response_field_value = self:connect_response_chain(xbdm_data, pinfo, response, tvb)
        if response_field_value then
            xbdm_data:add(response_field, response)
            pinfo.cols.info:set(response_field_value)
        else
            xbdm_data:add(is_binary_field, true)
            xbdm_data:add(raw_response_field, tvb(0, tvb:captured_len()))
            pinfo.cols.info:set("<DATA>")
        end

    end

    -- Processes the given packet the first time it is visited by the dissector.
    function ret:first_time_process_response_packet(command_number, command, response, tvb, pinfo)
        if self:chain_multiline_response(response, tvb, pinfo) then
            return true
        end

        if self:chain_binary_response(command_number, command, response, tvb, pinfo) then
            return true
        end

        return false
    end

    -- Add packet to multiline_response_packets if appropriate.
    -- Returns the packet number of the start of the chain if appended.
    function ret:chain_multiline_response(response, tvb, pinfo)
        if starts_with(response, "202") then
            self.multiline_response_packets[pinfo.number] = pinfo.number
            if tvb:range(-5, 5):string() == "\r\n.\r\n" then
                self.multiline_response_packets[pinfo.number] = -pinfo.number
                self.multiline_response_end_packets[pinfo.number] = pinfo.number
            end
            return pinfo.number
        end

        local _, last_multiline_packet_chain_start = find_closest_previous_or_same_packet(self.multiline_response_packets, pinfo.number)
        if last_multiline_packet_chain_start == nil then
            return nil
        end

        if last_multiline_packet_chain_start >= 0 then
            if starts_with(tvb:range(0, 3):string(), ".\r\n") then
                ---- Mark the end of a chain by saving the negated chain start.
                self.multiline_response_packets[pinfo.number] = -last_multiline_packet_chain_start
                self.multiline_response_end_packets[last_multiline_packet_chain_start] = pinfo.number
            else
                self.multiline_response_packets[pinfo.number] = last_multiline_packet_chain_start
            end

            return last_multiline_packet_chain_start
        end

        return nil
    end

    local LENGTH_PREFIXED_RESPONSE = {}

    local function get_binary_response_length_from_command(command)
        if starts_with(command, "getextcontext") then
            return LENGTH_PREFIXED_RESPONSE
        end

        if starts_with(command, "getmem2") then
            local binary_length = parse_size_param(command, "length")
            if binary_length == nil then
                print("Error: Missing length in command " .. command)
                return nil
            end
            return binary_length
        end

        return nil
    end

    -- Add packet to multiline_response_packets if appropriate.
    -- Returns the packet number of the start of the chain if appended.
    function ret:chain_binary_response(command_number, command, response, tvb, pinfo)
        if starts_with(response, "203") then
            local binary_length = get_binary_response_length_from_command(command)
            if binary_length == nil then
                print("Error: Missing binary length for command " .. command)
                return nil
            end

            self.binary_response_packets[pinfo.number] = table.pack(pinfo.number, binary_length)
            return pinfo.number
        end

        local _, last_chain_info = find_closest_previous_or_same_packet(self.binary_response_packets, pinfo.number)
        if last_chain_info == nil then
            return nil
        end

        local last_chain_start, remaining_bytes = table.unpack(last_chain_info)
        if remaining_bytes == 0 then
            return nil
        end

        if remaining_bytes == LENGTH_PREFIXED_RESPONSE then
            remaining_bytes = tonumber(tvb:range(0, 4):le_uint()) - (tvb:captured_len() - 4)
        else
            local is_retransmission = tcp_retransmission_field()
            if not is_retransmission then
                remaining_bytes = remaining_bytes - tvb:captured_len()
            end
        end

        self.binary_response_packets[pinfo.number] = table.pack(last_chain_start, remaining_bytes)
        if remaining_bytes == 0 then
            self.binary_response_end_packets[last_chain_start] = pinfo.number
        end
        return last_chain_start
    end

    -- Attempts to connect the given packet to an existing binary send request.
    -- Returns the packet number of the start of the chain, otherwise nil.
    function ret:chain_binary_send(command, tvb, pinfo)
        if starts_with(command, "sendfile") then
            local binary_length = parse_size_param(command, "length")
            if binary_length == nil then
                print("Error: Missing length in command " .. command)
                return nil
            end

            self.binary_send_packets[pinfo.number] = table.pack(pinfo.number, binary_length)
            return pinfo.number
        end

        local _, last_chain_info = find_closest_previous_or_same_packet(self.binary_send_packets, pinfo.number)
        if last_chain_info == nil then
            return nil
        end

        local last_chain_start, remaining_bytes = table.unpack(last_chain_info)
        if remaining_bytes == 0 then
            return nil
        end

        local is_retransmission = tcp_retransmission_field()
        if not is_retransmission then
            remaining_bytes = remaining_bytes - tvb:captured_len()
        end

        self.binary_send_packets[pinfo.number] = table.pack(last_chain_start, remaining_bytes)
        if remaining_bytes == 0 then
            self.binary_send_stream_end_packets[last_chain_start] = pinfo.number
        end
        return last_chain_start
    end

    -- Attempts to connect the given packet with the start of a multi-packet chain.
    -- Returns the value that should be set for the command field.
    function ret:connect_send_chain(xbdm_data, command, pinfo)
        local chain_info = self.binary_send_packets[pinfo.number]
        if chain_info ~= nil then
            local chain_start, _ = table.unpack(chain_info)
            if chain_start ~= pinfo.number then
                xbdm_data:add(binary_send_start_field, chain_start)
                xbdm_data:add(binary_send_end_field, self.binary_send_stream_end_packets[chain_start])
                return nil
            end
            return command
        end

        return command
    end

    -- Processes the given packet the first time it is visited by the dissector.
    function ret:first_time_process_request_packet(command, tvb, pinfo)
        self.packet_to_request[tonumber(pinfo.number)] = command

        local chain_start = self:chain_binary_send(command, tvb, pinfo)
        if chain_start ~= nil then
            self.packet_to_request[tonumber(pinfo.number)] = self.packet_to_request[chain_start]
            return
        end

        if starts_with(command, "notifyat port") then
            local port = register_notification_conversation(command)
            if port ~= nil then
                self.notification_registration_packets[pinfo.number] = port
            end
            return
        end
    end

    -- Populates the multiline/binary response fields for a packet.
    -- Returns the data that should be displayed in the info column.
    function ret:connect_response_chain(xbdm_data, pinfo, response, tvb)
        local chain_start = self.multiline_response_packets[pinfo.number]
        if chain_start ~= nil then
            if chain_start ~= pinfo.number then
                if chain_start < 0 then
                    chain_start = chain_start * -1
                end
                xbdm_data:add(multiline_response_start_field, chain_start)
                xbdm_data:add(multiline_response_end_field, self.multiline_response_end_packets[chain_start])

                if chain_start == self.multiline_response_end_packets[chain_start] then
                    return tvb:range(0, find_end_of_embedded_multiline(tvb, 0)):string()
                end
            end
            return response
        end

        local chain_info = self.binary_response_packets[pinfo.number]
        if chain_info ~= nil then
            chain_start, _ = table.unpack(chain_info)
            if chain_start == pinfo.number then
                return response
            end
            xbdm_data:add(binary_response_start_field, chain_start)
            xbdm_data:add(binary_response_end_field, self.binary_response_end_packets[chain_start])
            return nil
        end

        return response
    end

    return ret
end

-- Maps tcp.stream IDs to ConversationContext instances.
local conversations = {}
-- Maps tcp.stream IDs to NotificationConversationContext instances.
local notification_conversations = {}

local known_xbox_ports = {
    [731] = true,
    [1731] = true,  -- Development tunnel.
}

function xbdm_notification_dissector.dissector(tvb, pinfo, tree)
    -- obtain the current values the protocol fields
    local srcport = tcp_srcport_field()
    local dstport = tcp_dstport_field()
    local srcip = ip_src_field()
    local dstip = ip_dst_field()
    local tcp_stream = tcp_stream_field()

    if not (srcport and dstport and srcip and dstip and tcp_stream) then
        return
    end

    local sender_is_xbox = known_notification_ports[dstport.value]
    local sender_is_debugger = known_notification_ports[srcport.value]

    if not sender_is_xbox and not sender_is_debugger then
        print("Uninteresting packet " .. tostring(pinfo.number) .. " " .. tostring(srcport) .. " -> " .. tostring(dstport))
        return
    end

    pinfo.cols.protocol:set("XBDM-Notif")

    local xbdm_data = tree:add(xbdm_notification_dissector, "XBDM-Notification Data")
    xbdm_data:add(notification_sender_field, (sender_is_debugger and "XBDM" or "XBOX"))

    -- Ignore partial packets.
    if tvb:captured_len() ~= tvb:reported_length_remaining() then
        return
    end

    local tcp_stream_id = tcp_stream.value
    local conversation = notification_conversations[tcp_stream_id]
    if not conversation then
        conversation = NotificationConversationContext.new(tcp_stream_id)
        notification_conversations[tcp_stream_id] = conversation
    end

    if sender_is_xbox then
        conversation:process_notification(xbdm_data, tvb, pinfo)
    else
        print("Unexpectedly found computer->xbox packet in notification stream " .. tostring(pinfo.number))
    end
end

function xbdm_dissector.init()
    conversations = {}
    notification_conversations = {}
    known_xbox_ports = {
        [731] = true,
        [1731] = true,  -- Development tunnel.
    }
end

function xbdm_dissector.dissector(tvb, pinfo, tree)
    -- obtain the current values the protocol fields
    local srcport = tcp_srcport_field()
    local dstport = tcp_dstport_field()
    local srcip = ip_src_field()
    local dstip = ip_dst_field()
    local tcp_stream = tcp_stream_field()

    if not (srcport and dstport and srcip and dstip and tcp_stream) then
        return
    end

    local sender_is_xbox = known_xbox_ports[srcport.value]
    local sender_is_debugger = known_xbox_ports[dstport.value]

    if not sender_is_xbox and not sender_is_debugger then
        print("Uninteresting packet " .. tostring(pinfo.number) .. " " .. tostring(srcport) .. " -> " .. tostring(dstport))
        return
    end

    pinfo.cols.protocol:set("XBDM")

    local xbdm_data = tree:add(xbdm_dissector, "XBDM Data")
    xbdm_data:add(sender_field, (sender_is_debugger and "XBDM" or "XBOX"))

    -- Ignore partial packets.
    if tvb:captured_len() ~= tvb:reported_length_remaining() then
        return
    end

    local tcp_stream_id = tcp_stream.value
    local conversation = conversations[tcp_stream_id]
    if not conversation then
        conversation = ConversationContext.new(tcp_stream_id)
        conversations[tcp_stream_id] = conversation
    end

    if sender_is_xbox then
        conversation:process_response(xbdm_data, tvb, pinfo)
    else
        conversation:process_request(xbdm_data, tvb, pinfo)
    end
end

DissectorTable.get("tcp.port"):add(731, xbdm_dissector)
DissectorTable.get("tcp.port"):add(1731, xbdm_dissector)
