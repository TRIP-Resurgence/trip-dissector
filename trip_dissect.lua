trip_proto = Proto("TRIP", "Telephony Routing over IP")

trip_msg_len = ProtoField.uint16("trip.msg.len", "Message Length", base.DEC)
trip_msg_type = ProtoField.uint8("trip.msg.type", "Message Type", base.DEC)

trip_open_ver = ProtoField.uint8("trip.msg.open.ver", "Version", base.DEC)
trip_open_hold = ProtoField.uint16("trip.msg.open.hold", "Hold Time (s)", base.DEC)
trip_open_itad = ProtoField.uint32("trip.msg.open.itad", "ITAD", base.DEC)
trip_open_id = ProtoField.uint32("trip.msg.open.id", "ID", base.HEX)
trip_open_optslen = ProtoField.uint16("trip.msg.open.opts_len", "Optional Parameters Length", base.DEC)

trip_opt_type = ProtoField.uint16("trip.msg.open.opt.type", "Option Type", base.DEC)
trip_opt_len = ProtoField.uint16("trip.msg.open.opt.len", "Option Length", base.DEC)

trip_capinfo_code = ProtoField.uint16("trip.msg.open.opt.capinfo.code", "Capability Information Code", base.DEC)
trip_capinfo_len = ProtoField.uint16("trip.msg.open.opt.capinfo.len", "Capability Information Length", base.DEC)

trip_af = ProtoField.uint16("trip.af", "Address Family", base.DEC)
trip_appproto = ProtoField.uint16("trip.app_proto", "Application Protocol", base.DEC)
trip_transmode = ProtoField.uint16("trip.msg.open.opt.capinfo.transmode.mode", "Transmission Mode", base.DEC)

trip_attr_flags = ProtoField.uint8("trip.msg.update.attr.flags", "Flags", base.HEX)
trip_attr_type = ProtoField.uint8("trip.msg.update.attr.type", "Type", base.DEC)
trip_attr_len = ProtoField.uint16("trip.msg.update.attr.len", "Length", base.DEC)
trip_attr_id = ProtoField.uint32("trip.msg.update.attr.lsencap.id", "LSID", base.HEX)
trip_attr_seq = ProtoField.int32("trip.msg.update.attr.lsencap.seq", "Sequence number", base.DEC)

trip_route_len = ProtoField.uint16("trip.msg.update.attr.route.len", "Length", base.DEC)
trip_route_prefix = ProtoField.string("trip.msg.update.attr.route.pfx", "Prefix")

trip_notif_code = ProtoField.uint8("trip.msg.notif.code", "Code", base.DEC)
trip_notif_subcode = ProtoField.uint8("trip.msg.notif.subcode", "Subcode", base.DEC)

trip_proto.fields = {
	trip_msg_len,
	trip_msg_type,
	trip_open_ver,
	trip_open_hold,
	trip_open_itad,
	trip_open_id,
	trip_open_optslen,
	trip_opt_type,
	trip_opt_len,
	trip_capinfo_code,
	trip_capinfo_len,
	trip_af,
	trip_appproto,
	trip_transmode,
	trip_attr_flags,
	trip_attr_type,
	trip_attr_len,
	trip_attr_id,
	trip_attr_seq,
	trip_route_len,
	trip_route_prefix,
	trip_notif_code,
	trip_notif_subcode,
}

-- create a function to dissect it
function trip_proto.dissector(buffer, pinfo, tree)
	Length = buffer:len()
	if Length == 0 then
		return
	end

	pinfo.cols.protocol = "TRIP"
	local subtree = tree:add(trip_proto, buffer(), "TRIP Data")

	-- message header
	local msg_len = buffer(0, 2):le_uint()
	subtree:add_le(trip_msg_len, buffer(0, 2))

	local msg_type_num = buffer(2, 1):le_uint()
	subtree:add_le(trip_msg_type, buffer(2, 1)):append_text(" (" .. get_msg_type_name(msg_type_num) .. ")")

	-- message data
	if msg_type_num == 1 then
		local open_subtree = subtree:add(trip_proto, buffer(), "OPEN")

		local itad = buffer(7, 4):le_uint()
		local id = buffer(11, 4):le_uint()

		open_subtree:add_le(trip_open_ver, buffer(3, 1))
		open_subtree:add_le(trip_open_hold, buffer(5, 2))
		open_subtree:add_le(trip_open_itad, buffer(7, 4))
		open_subtree:add_le(trip_open_id, buffer(11, 4)):append_text(" (" .. ipv4_to_str(id) .. ")")
		open_subtree:add_le(trip_open_optslen, buffer(15, 2))

		local info_detail = itad .. ":" .. ipv4_to_str(id)

		local optslen = buffer(15, 2):le_uint()
		local optoff = 17
		while optslen > 0 do
			local opt_subtree = open_subtree:add(trip_proto, buffer(), "Optional Parameter")

			local opt_type_num = buffer(optoff, 2):le_uint()
			opt_subtree
				:add_le(trip_opt_type, buffer(optoff, 2))
				:append_text(" (" .. get_opt_type_name(opt_type_num) .. ")")
			opt_subtree:add_le(trip_opt_len, buffer(optoff + 2, 2))
			local optlen = buffer(optoff + 2, 2):le_uint()

			if opt_type_num == 1 then
				local capslen = optlen
				local capoff = 21
				while capslen > 0 do
					local capinfo_subtree = opt_subtree:add(trip_proto, buffer(), "Capability Information")

					local cap_code_num = buffer(capoff, 2):le_uint()
					capinfo_subtree
						:add_le(trip_capinfo_code, buffer(capoff, 2))
						:append_text(" (" .. get_capinfo_code_name(cap_code_num) .. ")")
					capinfo_subtree:add_le(trip_capinfo_len, buffer(capoff + 2, 2))
					local cap_len = buffer(capoff + 2, 2):le_uint()

					if cap_code_num == 1 then
						local routetype_off = capoff + 4
						local routetype_len = cap_len
						while routetype_len > 0 do
							local routetype_subtree = capinfo_subtree:add(trip_proto, buffer(), "Route Type")

							routetype_subtree
								:add_le(trip_af, buffer(routetype_off, 2))
								:append_text(" (" .. get_af_name(buffer(routetype_off, 2):le_uint()) .. ")")
							routetype_subtree
								:add_le(trip_appproto, buffer(routetype_off + 2, 2))
								:append_text(" (" .. get_appproto_name(buffer(routetype_off + 2, 2):le_uint()) .. ")")

							routetype_off = routetype_off + 4
							routetype_len = routetype_len - 4
						end
					elseif cap_code_num == 2 then
						local routetype_subtree = capinfo_subtree:add(trip_proto, buffer(), "Transmission Mode")
						routetype_subtree
							:add_le(trip_transmode, buffer(capoff + 4, 4))
							:append_text(" (" .. get_transmode_name(buffer(capoff + 4, 4):le_uint()) .. ")")
					end

					capoff = capoff + (4 + cap_len)
					capslen = capslen - (4 + cap_len)
				end
			end

			optslen = optslen - (4 + optlen)
			optoff = optoff + (4 + optlen)
		end

		pinfo.cols.info = "OPEN " .. info_detail
	elseif msg_type_num == 2 then
		local update_subtree = subtree:add(trip_proto, buffer(), "UPDATE")

		local info_detail = nil

		local attr_off = 3
		while msg_len > 0 do
			local attr_subtree = update_subtree:add(trip_proto, buffer(), "Attribute")

			local attr_flags = buffer(attr_off, 1):le_uint()
			local attr_type = buffer(attr_off + 1, 1):le_uint()
			local attr_len = buffer(attr_off + 2, 2):le_uint()

			attr_subtree:add_le(trip_attr_flags, buffer(attr_off, 1))
			attr_subtree
				:add_le(trip_attr_type, buffer(attr_off + 1, 1))
				:append_text(" (" .. get_attr_name(attr_type) .. ")")
			attr_subtree:add_le(trip_attr_len, buffer(attr_off + 2, 2))

			local attr_val_off = attr_off + 4
			if attr_flags & 8 == 1 then
				attr_subtree:add_le(trip_attr_id, buffer(attr_off + 4, 4))
				attr_subtree:add_le(trip_attr_seq, buffer(attr_off + 8, 4))
				attr_val_off = attr_val_off + 8
			end

			if attr_type == 1 then
				local routes_subtree = attr_subtree:add(trip_proto, buffer(), "WithdrawnRoutes")
				local rcount = dissect_routes(routes_subtree, buffer, attr_len, attr_val_off)
				info_detail = "WithdrawnRoutes[" .. rcount .. "]"
			elseif attr_type == 2 then
				local routes_subtree = attr_subtree:add(trip_proto, buffer(), "ReachableRoutes")
				local rcount = dissect_routes(routes_subtree, buffer, attr_len, attr_val_off)
				info_detail = "ReachableRoutes[" .. rcount .. "]"
			end

			msg_len = msg_len - ((attr_val_off + attr_len) - attr_off)
			attr_off = attr_val_off + attr_len
		end

		pinfo.cols.info = "UPDATE " .. info_detail
	elseif msg_type_num == 3 then
		local notif_subtree = subtree:add(trip_proto, buffer(), "NOTIFICATION")

		local code = buffer(3, 1):le_uint()
		local subcode = buffer(4, 1):le_uint()

		notif_subtree:add_le(trip_notif_code, buffer(3, 1)):append_text(" (" .. get_code_name(code) .. ")")
		notif_subtree
			:add_le(trip_notif_subcode, buffer(4, 1))
			:append_text(" (" .. get_subcode_name(code, subcode) .. ")")

		pinfo.cols.info = "NOTIFICATION " .. get_code_name(code) .. "," .. get_subcode_name(code, subcode)
	elseif msg_type_num == 4 then
		pinfo.cols.info = "KEEPALIVE"
	end
end

function dissect_routes(tree, buffer, attr_len, route_off)
	local count = 0
	while attr_len > 0 do
		local route_subtree = tree:add(trip_proto, buffer(), "Route")

		local prefix_len = buffer(route_off + 4, 2):le_uint()
		route_subtree
			:add_le(trip_af, buffer(route_off, 2))
			:append_text(" (" .. get_af_name(buffer(route_off, 2):le_uint()) .. ")")
		route_subtree
			:add_le(trip_appproto, buffer(route_off + 2, 2))
			:append_text(" (" .. get_appproto_name(buffer(route_off + 2, 2):le_uint()) .. ")")
		route_subtree:add_le(trip_route_len, buffer(route_off + 4, 2))
		route_subtree:add_le(trip_route_prefix, buffer(route_off + 6, prefix_len))

		attr_len = attr_len - ((route_off + 6 + prefix_len) - route_off)
		route_off = route_off + 6 + prefix_len
		count = count + 1
	end
	return count
end

function ipv4_to_str(ip)
	return string.format("%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff)
end

function get_str_len(buffer, off)
	local string_length
	for i = off, Length - 1, 1 do
		if buffer(i, 1):le_uint() == 0 then
			string_length = i - off
			break
		end
	end
	return string_length
end

function get_msg_type_name(type_num)
	local type_name = "Unknown"

	if type_num == 1 then
		type_name = "OPEN"
	elseif type_num == 2 then
		type_name = "UPDATE"
	elseif type_num == 3 then
		type_name = "NOTIFICATION"
	elseif type_num == 4 then
		type_name = "KEEPALIVE"
	end

	return type_name
end

function get_opt_type_name(type_num)
	local type_name = "Unknown"

	if type_num == 1 then
		type_name = "Capability Information"
	end

	return type_name
end

function get_capinfo_code_name(code_num)
	local code_name = "Unknown"

	if code_num == 1 then
		code_name = "Route Type"
	elseif code_num == 2 then
		code_name = "Transmission Mode"
	end

	return code_name
end

function get_af_name(af)
	local name = "Unknown"

	if af == 1 then
		name = "Decimal"
	elseif af == 2 then
		name = "Pentadecimal"
	elseif af == 3 then
		name = "E.164"
	elseif af == 4 then
		name = "Trunk Group"
	elseif af == 32768 then
		name = "Carrier"
	end

	return name
end

function get_appproto_name(appproto)
	local name = "Unknown"

	if appproto == 1 then
		name = "SIP"
	elseif appproto == 2 then
		name = "H.323-H.225.0-Q.931"
	elseif appproto == 3 then
		name = "H.323-H.225.0-RAS"
	elseif appproto == 4 then
		name = "H.323-H.225.0-Annex-G"
	elseif appproto == 32768 then
		name = "IAX2"
	end

	return name
end

function get_transmode_name(transmode)
	local name = "Unknown"

	if transmode == 1 then
		name = "Duplex"
	elseif transmode == 2 then
		name = "Send only"
	elseif transmode == 3 then
		name = "Receive only"
	end

	return name
end

function get_attr_name(attr)
	local name = "Unknown"

	if attr == 1 then
		name = "WithdrawnRoutes"
	elseif attr == 2 then
		name = "ReachableRoutes"
	elseif attr == 3 then
		name = "NextHopServer"
	elseif attr == 4 then
		name = "AdvertisementPath"
	elseif attr == 5 then
		name = "RoutedPath"
	elseif attr == 6 then
		name = "AtomicAggregate"
	elseif attr == 7 then
		name = "LocalPreference"
	elseif attr == 8 then
		name = "MultiExitDiscriminator"
	elseif attr == 9 then
		name = "Communities"
	elseif attr == 10 then
		name = "ITAD Topology"
	elseif attr == 11 then
		name = "ConvertedRoute"
	end

	return name
end

function get_code_name(code)
	local name = "Unknown"

	if code == 1 then
		name = "Message"
	elseif code == 2 then
		name = "Open"
	elseif code == 3 then
		name = "Update"
	elseif code == 4 then
		name = "Expired"
	elseif code == 5 then
		name = "State"
	elseif code == 6 then
		name = "Cease"
	end

	return name
end

function get_subcode_name(code, subcode)
	local name = "Unknown"

	if code == 1 then
		if subcode == 1 then
			name = "Bad length"
		elseif subcode == 2 then
			name = "Bad type"
		end
	elseif code == 2 then
		if subcode == 1 then
			name = "Unsupported version"
		elseif subcode == 2 then
			name = "Bad ITAD"
		elseif subcode == 3 then
			name = "Bad ID"
		elseif subcode == 4 then
			name = "Unsupported option"
		elseif subcode == 5 then
			name = "Bad hold time"
		elseif subcode == 6 then
			name = "Unsupported capability"
		elseif subcode == 7 then
			name = "Transmission mode mismatch"
		end
	elseif code == 3 then
		if subcode == 1 then
			name = "Malformed attribute"
		elseif subcode == 2 then
			name = "Unknown well-known attribute"
		elseif subcode == 3 then
			name = "Missing well-known flag"
		elseif subcode == 4 then
			name = "Bad attribute flag"
		elseif subcode == 5 then
			name = "Bad attribute length"
		elseif subcode == 6 then
			name = "Invalid attribute"
		end
	else
		name = "Unused"
	end

	return name
end

tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(6069, trip_proto)

print("test")
