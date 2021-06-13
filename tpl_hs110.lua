hs110_protocol = Proto("HS110", "TP Link HS110 Protocol")

msg_len = ProtoField.int16("hs110.message_length", "Message Length", base.DEC)
message = ProtoField.string("hs110.str", "Decoded Message", base.ASCII)

hs110_protocol.fields = { msg_len, message }

function hs110_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = hs110_protocol.name

  local subtree = tree:add(hs110_protocol, buffer(), "TP Link HS110 Data")

  subtree:add(msg_len, buffer(0,4))
  --subtree:add(message, buffer(4))
  subtree:add(message, decrypt(buffer:bytes(4)))
end

function decrypt(ciphertext)
  local key = 171
  local plaintext = ""
  for i = 0, ciphertext:len()-1, 1 do
    plaintext = plaintext .. string.char(bit32.bxor(ciphertext:get_index(i), key))
    key = ciphertext:get_index(i)
  end
  return plaintext
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9999, hs110_protocol)
