trip_proto = Proto("TRIP", "Telephony Routing over IP")

trip_msg_len = ProtoField.uint16("trip.msg.len", "Message Length", base.DEC)
trip_msg_type = ProtoField.uint8("trip.msg.type", "Message Type", base.DEC)

trip_open_ver = ProtoField.uint8("trip.msg.open.ver", "Version", base.DEC)
trip_open_hold = ProtoField.uint16("trip.msg.open.hold", "Hold Time (s)", base.DEC)
trip_open_itad = ProtoField.uint16("trip.msg.open.itad", "ITAD", base.DEC)
trip_open_id = ProtoField.uint16("trip.msg.open.id", "ID", base.HEX)
trip_open_optslen = ProtoField.uint16("trip.msg.open.opts_len", "Optional Parameters Length", base.DEC)

trip_opt_type = ProtoField.uint16("trip.msg.open.opt.type", "Option Type", base.DEC)
trip_opt_len = ProtoField.uint16("trip.msg.open.opt.len", "Option Length", base.DEC)

trip_capinfo_code = ProtoField.uint16("trip.msg.open.opt.capinfo.code", "Capability Information Code", base.DEC)
trip_capinfo_len = ProtoField.uint16("trip.msg.open.opt.capinfo.len", "Capability Information Length", base.DEC)

trip_af = ProtoField.uint16("trip.af", "Address Family", base.DEC)
trip_appproto = ProtoField.uint16("trip.app_proto", "Application Protocol", base.DEC)
trip_transmode = ProtoField.uint16("trip.msg.open.opt.capinfo.transmode.mode", "Transmission Mode", base.DEC)

trip_proto.fields = { trip_msg_len, trip_msg_type, trip_open_ver, trip_open_hold, trip_open_itad, trip_open_id, trip_open_optslen, trip_opt_type, trip_opt_len, trip_capinfo_code, trip_capinfo_len, trip_af, trip_appproto, trip_transmode }

-- create a function to dissect it
function trip_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = "TRIP"
    local subtree = tree:add(trip_proto, buffer(), "TRIP Data")

    -- message header
    local msg_len = buffer(2,1):le_uint()
    subtree:add_le(trip_msg_len, buffer(0,2))

    local msg_type_num = buffer(2,1):le_uint()
    subtree:add_le(trip_msg_type, buffer(2,1)):append_text(" (" .. get_msg_type_name(msg_type_num) .. ")")

    -- message data
    if msg_type_num == 1 then 
        local open_subtree = subtree:add(trip_proto, buffer(), "OPEN")

        open_subtree:add_le(trip_open_ver, buffer(3,1))
        open_subtree:add_le(trip_open_hold, buffer(5,2))
        open_subtree:add_le(trip_open_itad, buffer(7,4))
        open_subtree:add_le(trip_open_id, buffer(11,4))
        open_subtree:add_le(trip_open_optslen, buffer(15,2))

        local optslen = buffer(15,2):le_uint()
        local optoff = 17
        while optslen > 0 do
            local opt_subtree = open_subtree:add(trip_proto, buffer(), "Optional Parameter")

            local opt_type_num = buffer(optoff,2):le_uint()
            opt_subtree:add_le(trip_opt_type, buffer(optoff,2)):append_text(" (" .. get_opt_type_name(opt_type_num) .. ")")
            opt_subtree:add_le(trip_opt_len, buffer(optoff+2,2))
            optlen = buffer(optoff+2,2):le_uint()

            if opt_type_num == 1 then

                local capslen = optlen
                local capoff = 21
                while capslen > 0 do
                    local capinfo_subtree = opt_subtree:add(trip_proto, buffer(), "Capability Information")

                    local cap_code_num = buffer(capoff,2):le_uint()
                    capinfo_subtree:add_le(trip_capinfo_code, buffer(capoff,2)):append_text(" (" .. get_capinfo_code_name(cap_code_num) .. ")")
                    capinfo_subtree:add_le(trip_capinfo_len, buffer(capoff+2,2))
                    local cap_len = buffer(capoff+2,2):le_uint()

                    if cap_code_num == 1 then
                        
                        local routetype_off = capoff+4
                        local routetype_len = cap_len
                        while routetype_len > 0 do
                            local routetype_subtree = capinfo_subtree:add(trip_proto, buffer(), "Route Type")

                            routetype_subtree:add_le(trip_af, buffer(routetype_off,2)):append_text(" (" .. get_af_name(buffer(routetype_off,2):le_uint()) .. ")")
                            routetype_subtree:add_le(trip_appproto, buffer(routetype_off+2,2)):append_text(" (" .. get_appproto_name(buffer(routetype_off+2,2):le_uint()) .. ")")

                            routetype_off = routetype_off + 4
                            routetype_len = routetype_len - 4
                        end
                    elseif cap_code_num == 2 then
                        local routetype_subtree = capinfo_subtree:add(trip_proto, buffer(), "Transmission Mode")
                        routetype_subtree:add_le(trip_transmode, buffer(capoff+4,4)):append_text(" (" .. get_transmode_name(buffer(capoff+4,4):le_uint()) .. ")")
                    end

                    capoff = capoff + (4 + cap_len)
                    capslen = capslen - (4 + cap_len)
                end
            
            end

            optslen = optslen - (4 + optlen)
            optoff = optoff + (4 + optlen)
        end
    elseif msg_type_num == 2 then 
    elseif msg_type_num == 3 then
    elseif msg_type_num == 4 then 
    end
end

function get_str_len(buffer, off)
    local string_length
    for i = off, length - 1, 1 do
      if (buffer(i,1):le_uint() == 0) then
        string_length = i - off
        break
      end
    end
    return string_length
end

function get_msg_type_name(type_num)
    local type_name = "Unknown"
  
    if type_num == 1 then type_name = "OPEN"
    elseif type_num == 2 then type_name = "UPDATE"
    elseif type_num == 3 then type_name = "NOTIFICATION"
    elseif type_num == 4 then type_name = "KEEPALIVE" end
  
    return type_name
end

function get_opt_type_name(type_num)
    local type_name = "Unknown"
  
    if type_num == 1 then type_name = "Capability Information" end
  
    return type_name
end

function get_capinfo_code_name(code_num)
    local code_name = "Unknown"

    if code_num == 1 then code_name = "Route Type"
    elseif code_num == 2 then code_name = "Transmission Mode"
    end
    
    return code_name
end

function get_af_name(af)
    local name = "Unknown"

    if af == 1 then name = "Decimal"
    elseif af == 2 then name = "Pentadecimal"
    elseif af == 3 then name = "E.164"
    elseif af == 4 then name = "Trunk Group"
    elseif af == 32768 then name = "Carrier"
    end

    return name
end

function get_appproto_name(appproto)
    local name = "Unknown"

    if appproto == 1 then name = "SIP"
    elseif appproto == 2 then name = "H.323-H.225.0-Q.931"
    elseif appproto == 3 then name = "H.323-H.225.0-RAS"
    elseif appproto == 4 then name = "H.323-H.225.0-Annex-G"
    elseif appproto == 32768 then name = "IAX2"
    end

    return name
end

function get_transmode_name(transmode)
    local name = "Unknown"

    if transmode == 1 then name = "Duplex"
    elseif transmode == 2 then name = "Send only"
    elseif transmode == 3 then name = "Receive only"
    end

    return name
end
  

tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(6069, trip_proto)

print("test")

