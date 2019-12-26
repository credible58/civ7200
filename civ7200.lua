------------------------------------------------- 
-- CI-V IC-7200 postdissector -- 
------------------------------------------------- 

------------------------------------------------- 
-- License - GNU GPL v3 
--      see http://www.gnu.org/licenses/gpl.html 
------------------------------------------------- 

------------------------History-------------------------- 
-- r1 - pjo - Initial release 
-- 
--------------------------------------------------------- 

-- Execution controls ------------------------------------- 
debug_set = false
go_bang = {} 
-- End of Execution Controls ------------------------------ 

VALS_NULL = {
  [0] = ""
}

VALS_OPMODE = {
  [0] = "LSB mode",
  [1] = "USB mode",
  [2] = "AM mode",
  [3] = "CW mode",
  [4] = "RTTY mode",
  [5] = "Unknown mode",
  [6] = "Unknown mode",
  [7] = "CW-R mode",
  [8] = "RTTY-R mode"
}

VALS_FILTSET = {
  [0] = "unknown",
  [1] = "Wide",
  [2] = "Mid",
  [3] = "Narrow"
}

VALS_SROP = {
  [0] = "Send/read memory contents",
  [1] = "Send/read band stacking register contents",
  [2] = "Send/read the selected filter width",
  [3] = "Send/read various",
  [4] = "Send/read DATA mode",
  [5] = "Send/read Sharp/Soft selection",
  [6] = "Send/read manual notch width"
}

VALS_CMD = {
  [0] = "Send frequency data",
  [1] = "Select transceive mode",
  [2] = "Read band edge frequency",
  [3] = "Read operating frequency",
  [4] = "Read operating mode",
  [5] = "Set operating frequency",
  [6] = "Select operating mode",
  [7] = "Select VFO mode",
  [8] = "Select memory mode / channel",
  [9] = "Memory write",
  [10] = "Memory to VFO",
  [11] = "Memory clear",
  [12] = "Unknown command",
  [13] = "Unknown command",
  [14] = "Scan control",
  [15] = "Split function",
  [16] = "Select tuning steps",
  [17] = "Control attenuator",
  [18] = "Unknown command",
  [19] = "Voice synthesizer control",
  [20] = "Set levels",
  [21] = "Read squelch and meters",
  [22] = "Control transceiver operations",
  [23] = "Unknown command",
  [24] = "Unknown command",
  [25] = "Read transceiver ID",
  [26] = "Send and read operations",
  [27] = "Unknown command",
  [28] = "Send/read transceiver status"
}

-- format of entry: subcmd, has_subsub_cmd, reserved, description
subcmd_opmode_table= {
	{ 0x00, 0, 0, "LSB mode" },
	{ 0x01, 0, 0, "USB mode" },
	{ 0x02, 0, 0, "AM mode" },
	{ 0x03, 0, 0, "CW mode" },
	{ 0x04, 0, 0, "RTTY mode" },
	{ 0x05, 0, 0, "Unknown mode" },
	{ 0x06, 0, 0, "Unknown mode" },
	{ 0x07, 0, 0, "CW-R mode" },
	{ 0x08, 0, 0, "RTTY-R mode" },
        { 0xff, 0, 0, "end of table" }
}

subcmd_vfomode_table= {
	{ 0x00, 0, 0, "Select VFO A" },
	{ 0x01, 0, 0, "Select VFO B" },
	{ 0xa0, 0, 0, "Equalize VFO A and VFO B" },
	{ 0xb0, 0, 0, "Exchange VFO A and VFO B" },
        { 0xff, 0, 0, "end of table" }
}

subcmd_srop_table = {
	{ 0x00, 0, 0, "Send/read memory contents" },
	{ 0x01, 0, 0, "Send/read band stacking register contents" },
	{ 0x02, 0, 0, "Send/read the selected filter width" },
	{ 0x03, 1, 0, "Send/read various" },
	{ 0x04, 0, 0, "Send/read DATA mode" },
	{ 0x05, 0, 0, "Send/read Sharp/Soft selection" },
	{ 0x06, 0, 0, "Send/read manual notch width" },
        { 0xff, 0, 0, "end of table" }
}

subcmd_transtuner_table= {
	{ 0x00, 0, 0, "Send/read the transceiver’s status" },
	{ 0x01, 0, 0, "Send/read antenna tuner" },
        { 0xff, 0, 0, "end of table" }
}

-- declare the extractors for some Fields to be read 
-- these work like getters 
frame_number_f = Field.new("frame.number") 
usb_src_f = Field.new("usb.src") 
usb_dst_f = Field.new("usb.dst") 
usb_direction_f = Field.new("usb.irp_info.direction")  -- 0 = H->D and 1 = D->H 
usb_transfer_type_f = Field.new("usb.transfer_type")
usb_data_len_f = Field.new("usb.data_len")
usbms_dCBWSignature_f = Field.new("usbms.dCBWSignature")
usbms_dCSWSignature_f = Field.new("usbms.dCSWSignature")
civ_msg_f = Field.new("usb.capdata")

-- declare the civ7200 as a protocol 
civ7200 = Proto("civ7200","CI-V 7200 Postdissector") 

civ_delim_start  = ProtoField.uint16("civ7200.delim_start", "Start Delimiter",     base.HEX) 
civ_dst_addr     = ProtoField.uint8("civ7200.dst_addr",     "Destination Address", base.HEX) 
civ_src_addr     = ProtoField.uint8("civ7200.src_addr",     "Source Address",      base.HEX)
civ_cmd          = ProtoField.uint8("civ7200.cmd",          "Command",             base.HEX,  VALS_CMD)

civ_subcmd01     = ProtoField.uint8("civ7200.subcmd",       "Sub-command",         base.HEX,  VALS_OPMODE)
civ_subcmd06     = ProtoField.uint8("civ7200.subcmd",       "Sub-command",         base.HEX,  VALS_OPMODE)
civ_subcmd26     = ProtoField.uint8("civ7200.subcmd",       "Sub-command",         base.HEX,  VALS_SROP)

civ_data         = ProtoField.string("civ7200.data",        "Data")
civ_opmode       = ProtoField.uint8("civ7200.opmode",       "Data",                base.HEX,  VALS_OPMODE)
civ_filtset      = ProtoField.uint8("civ7200.filtset",      "Data",                base.HEX,  VALS_FILTSET)

civ_delim_end    = ProtoField.uint8("civ7200.delim_end",    "End Delimiter",       base.HEX) 
civ_freq         = ProtoField.uint32("civ7200.frequency",   "Frequency",           base.DEC)
civ7200.fields = {
  civ_delim_start, civ_dst_addr, civ_src_addr, civ_cmd, 
  civ_subcmd01, civ_subcmd06, civ_subcmd26,
  civ_opmode, civ_filtset,
  civ_data, civ_freq, civ_delim_end
} 


civ7200_invalid = ProtoExpert.new("civ7200.invalid", "civ7200 Invalid CI-V message", expert.group.SEQUENCE, expert.severity.WARN) 
civ7200.experts = {civ7200_invalid} 

-- register our postdissector
register_postdissector(civ7200)

-- format of entry: cmd, has_subcmd, subcmd_table, description
cmd_table = {
	{ 0x00, 0, 0, "Send frequency data", 0 },
	{ 0x01, 1, subcmd_opmode_table, "Select transceive mode", civ_subcmd01 },
	{ 0x02, 0, 0, "Read band edge frequency", 0 },
	{ 0x03, 0, 0, "Read operating frequency", 0 },
	{ 0x04, 0, 0, "Read operating mode", 0 },
	{ 0x05, 0, 0, "Set operating frequency", 0 },
	{ 0x06, 1, subcmd_opmode_table, "Select operating mode", civ_subcmd06 },
	{ 0x07, 1, subcmd_vfomode_table, "Select VFO mode", 0 },
	{ 0x08, 1, 0, "Select memory mode / channel", 0 },
	{ 0x09, 0, 0, "Memory write", 0 },
	{ 0x0a, 0, 0, "Memory to VFO", 0 },
	{ 0x0b, 0, 0, "Memory clear", 0 },
	{ 0x0e, 1, 0, "Scan control", 0 },
	{ 0x0f, 1, 0, "Split function", 0 },
	{ 0x10, 1, 0, "Select tuning steps", 0 },
	{ 0x11, 0, 0, "Control attenuator", 0 },
	{ 0x13, 1, 0, "Voice synthesizer control", 0 },
	{ 0x14, 1, 0, "Set levels", 0 },
	{ 0x15, 1, 0, "Read squelch and meters", 0 },
	{ 0x16, 1, 0, "Control transceiver operations", 0 },
	{ 0x19, 0, 0, "Read transceiver ID", 0 },
	{ 0x1a, 1, subcmd_srop_table, "Send and read operations", civ_subcmd26 },
	{ 0x1c, 1, subcmd_transtuner_table, "Send/read transceiver status", 0 },
	{ 0xff, 0, 0, "end of table", 0 }
}

-- This function gets called when a new trace file is loaded 
function civ7200.init() 
  if debug_set then print("Entering: civ7200.init()") end 
end 

-- This function returns a non-zero length is this is a valid CI-V message

function getCivLength(buffer) 
  if debug_set then print("Entering: civ7200.packet_check()") end

  local is_usbms = usbms_dCSWSignature_f()

  if is_usbms then
    return 0
  end

  local is_usbms = usbms_dCBWSignature_f()

  if is_usbms then
    return 0
  end

  civ_length = usb_data_len_f().value

  if civ_length >= 6 then
    if tonumber(usb_transfer_type_f().value) == 3 then
      local ptr = buffer:len() - civ_length
      tvbr = buffer:range(ptr,2)  -- set up a range
      local delim = tvbr:uint()  -- extract the bytes
      if delim == 0xfefe then
        return civ_length
      end
    end
  end

  return 0
end 

function get_freq_u32(buffer, ptr)
  local freq_u32 = 0
  local tvbr
  local byte_in_hex

  -- in case we enter here by mistake we need to make sure
  -- we have enough bytes to consume
  if (ptr + 4) > (buffer:len() - 1) then
    return 0
  end

  tvbr = buffer:range(ptr+4,1)  -- set up a range
  byte_in_hex = tvbr:uint()  -- extract the byte
  freq_u32 = freq_u32 + (bit.rshift(byte_in_hex, 4) * 1000000000)
  freq_u32 = freq_u32 + (bit.band(byte_in_hex,0x0f) * 100000000)
  tvbr = buffer:range(ptr+3,1)  -- set up a range
  byte_in_hex = tvbr:uint()  -- extract the byte
  freq_u32 = freq_u32 + (bit.rshift(byte_in_hex, 4) * 10000000)
  freq_u32 = freq_u32 + (bit.band(byte_in_hex,0x0f) * 1000000)
  tvbr = buffer:range(ptr+2,1)  -- set up a range
  byte_in_hex = tvbr:uint()  -- extract the byte
  freq_u32 = freq_u32 + (bit.rshift(byte_in_hex, 4) * 100000)
  freq_u32 = freq_u32 + (bit.band(byte_in_hex,0x0f) * 10000)
  tvbr = buffer:range(ptr+1,1)  -- set up a range
  byte_in_hex = tvbr:uint()  -- extract the byte
  freq_u32 = freq_u32 + (bit.rshift(byte_in_hex, 4) * 1000)
  freq_u32 = freq_u32 + (bit.band(byte_in_hex,0x0f) * 100)
  tvbr = buffer:range(ptr+0,1)  -- set up a range
  byte_in_hex = tvbr:uint()  -- extract the byte
  freq_u32 = freq_u32 + (bit.rshift(byte_in_hex, 4) * 10)
  freq_u32 = freq_u32 + (bit.band(byte_in_hex,0x0f) * 1)

  return freq_u32
end

function civ7200.dissector(buffer,pinfo,tree) 

  local info_text 
  local civ_msg
  local cmd
  local civ_dstaddr
  local civ_srcaddr
  local ptr = 0
  local data_offset
  local tvbr
  local frequency -- string version of the fequency
  local subcmd_table
  local cmd_string
  local subcmd_string
  local subcmd_vals
  local i -- cmd_table index
  local j -- subcmd_table index

  local length = buffer:len()
  if length == 0 then return end

  if pinfo.visited then 
    civ_length = getCivLength(buffer) 

    if civ_length > 0 then 
      if debug_set then print("Processing CI-V message") end
      pinfo.cols.protocol = civ7200.name

      vals = {}
      ptr = length - civ_length

      local subtree = tree:add(civ7200, buffer(), "CI-V Protocol")

      ptr = length - civ_length
      subtree:add(civ_delim_start, buffer(ptr,2))
      ptr = ptr + 2
      subtree:add(civ_dst_addr, buffer(ptr,1))
      tvbr = buffer:range(ptr,1)  -- set up a range
      civ_dstaddr = tvbr:uint()  -- extract the bytes
      ptr = ptr + 1
      subtree:add(civ_src_addr, buffer(ptr,1))
      tvbr = buffer:range(ptr,1)  -- set up a range
      civ_srcaddr = tvbr:uint()  -- extract the bytes
      ptr = ptr + 1

      tvbr = buffer:range(ptr,1)  -- set up a range
      cmd = tvbr:uint()  -- extract the bytes
      subtree:add(civ_cmd, buffer(ptr,1))
      ptr = ptr + 1

      local has_subcmd = false
      i = 1
      j = 1
      cmd_string = ""
      subcmd_string = ""

      -- look up command details
      while(cmd_table[i][1] ~= 0xff)
      do
        if cmd_table[i][1] == cmd then
          cmd_string = cmd_table[i][4]
          if cmd_table[i][2] == 1 then
            has_subcmd = true
            subcmd_table = cmd_table[i][3]
            subcmd_vals = cmd_table[i][5]
            break;
          end
        end
        i = i + 1
      end

      -- process sub cmd
      if has_subcmd == true then
        tvbr = buffer:range(ptr,1)  -- set up a range
        subcmd = tvbr:uint()  -- extract the bytes

        proto_field = cmd_table[i][5]
        subtree:add(proto_field, buffer(ptr,1))
        ptr = ptr + 1

        if subcmd_table then
          while(subcmd_table[j][1] ~= 0xff)
          do
            if subcmd_table[j][1] == subcmd then
              subcmd_string = subcmd_table[j][4]
            end
          j = j + 1
          end
        end

        cmd_string = cmd_string .. ":" .. subcmd_string
      end

      data_offset = ptr
      data_len = length - data_offset - 1
      if data_len > 0 then
        tvbr = buffer:range(ptr,data_len)  -- set up a range
        local civ_payload = tvbr:bytes()  -- extract the bytes

        if(cmd == 0x00 or cmd == 0x02 or cmd == 0x03 or cmd == 0x05) then
          freq = get_freq_u32(buffer, ptr)
          subtree:add(civ_freq, freq)
          cmd_string = cmd_string .. ": " .. freq
       else
          subtree:add(civ_data, tostring(civ_payload))
        end
        ptr = ptr + data_len

        if(cmd == 0x04 and civ_dstaddr == 0xE0) then
          tvbr = buffer:range(data_offset,1)  -- set up a range
          subtree:add(civ_opmode, tvbr:uint())
          cmd_string = cmd_string .. ": " .. VALS_OPMODE[tvbr:uint()]

          tvbr = buffer:range(data_offset+1,1)  -- set up a range
          subtree:add(civ_filtset, tvbr:uint())
          cmd_string = cmd_string .. "/" .. VALS_FILTSET[tvbr:uint()]
        end
      end

      subtree:add(civ_delim_end,  buffer(ptr,1))

      -- Set the Info column text
      if civ_srcaddr == 0xE0 then
        if tonumber(usb_direction_f().value) == 1 then
          info_text = "CI-V Echo: " .. cmd_string
        else
          info_text = "CI-V Cmd: " .. cmd_string
        end
      else
        if cmd_string == "" then
          info_text = "CI-V Ack"
        else
          info_text = "CI-V Rsp: " .. cmd_string
        end
      end

      pinfo.cols.info:set(info_text) 
      pinfo.cols.info:fence() 
    else 
      if debug_set then print("SNAP02") end 
    end 

    if debug_set then print("SNAP03") end 
  end 
end 

