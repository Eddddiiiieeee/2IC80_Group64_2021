-- declare protocol HS110
hs110_protocol = Proto("HS110", "TP Link HS110 Protocol")

-- protocol fields
msg_len = ProtoField.int16("hs110.message_length", "Message Length", base.DEC)
message = ProtoField.string("hs110.str", "Decoded Message", base.ASCII)
hs110_protocol.fields = { msg_len, message }

-- dissector function for the HS110 protocol
function hs110_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = hs110_protocol.name

  local subtree = tree:add(hs110_protocol, buffer(), "TP Link HS110 Data")

  -- assign 'msg_len' to be the first 4 bytes
  subtree:add(msg_len, buffer(0,4))

  -- assign 'message' to be the rest of the data, decrypted
  subtree:add(message, decrypt(buffer:bytes(4)))
end

-- decryption function for the TP-Link HS110 protocol
function decrypt(ciphertext)
  local key = 171
  local plaintext = ""
  for i = 0, ciphertext:len()-1, 1 do
    plaintext = plaintext .. string.char(bit32.bxor(ciphertext:get_index(i), key))
    key = ciphertext:get_index(i)
  end
  return plaintext
end

-- load tcp.port table and bind protocol to port 9999
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9999, hs110_protocol)