-- Disector de Wireshark para el protocolo RDT (Stop and Wait)
-- Uso: wireshark -X lua_script:rdt_saw.lua
-- o copiarlo a ~/.local/lib/wireshark/plugins/ y reiniciar Wireshark.
-- El puerto UDP se cambia en Edit > Preferences > Protocols > RDT.

local rdt = Proto("SAW", "SAW Protocol ")

local DEFAULT_PORT = 5000
local HEADER_SIZE = 3

rdt.prefs.port = Pref.uint("UDP port", DEFAULT_PORT, "Puerto UDP del servidor SAW")

local type_names = { [0] = "Stop and Wait", [1] = "SACK" }
local op_names   = { [0] = "DOWNLOAD", [1] = "UPLOAD" }
local err_names  = {
    [0] = "Sin error",
    [1] = "Nombre de archivo invalido",
    [2] = "El archivo ya existe en el servidor",
    [3] = "El archivo es demasiado grande",
}
local bool_names = { "Set", "Not set" }

local f = rdt.fields
f.seq     = ProtoField.uint8("rdt.seq", "Sequence Number", base.DEC)
f.ack_num = ProtoField.uint8("rdt.ack_num", "Ack Number", base.DEC)
f.flags   = ProtoField.uint8("rdt.flags", "Flags", base.HEX)
f.f_type  = ProtoField.uint8("rdt.flags.type", "Tipo", base.DEC, type_names, 0x80)
f.f_op    = ProtoField.uint8("rdt.flags.op", "Operacion", base.DEC, op_names, 0x40)
f.f_ack   = ProtoField.bool("rdt.flags.ack", "ACK", 8, bool_names, 0x20)
f.f_syn   = ProtoField.bool("rdt.flags.syn", "SYN", 8, bool_names, 0x10)
f.f_fin   = ProtoField.bool("rdt.flags.fin", "FIN", 8, bool_names, 0x08)
f.f_error = ProtoField.uint8("rdt.flags.error", "Codigo de error", base.DEC, err_names, 0x07)

f.payload     = ProtoField.bytes("rdt.payload", "Payload")
f.payload_len = ProtoField.uint32("rdt.payload_len", "Largo del payload", base.DEC)

-- MessageSynUpload
f.file_size = ProtoField.uint24("rdt.syn.file_size", "Tamano del archivo (bytes)", base.DEC)
f.fn_len    = ProtoField.uint8("rdt.syn.file_name_len", "Largo del nombre", base.DEC)
f.file_name = ProtoField.string("rdt.syn.file_name", "Nombre del archivo")


function rdt.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len < HEADER_SIZE then return 0 end

    pinfo.cols.protocol = "SAW"

    local seq   = buffer(0, 1):uint()
    local ackn  = buffer(1, 1):uint()
    local flags = buffer(2, 1):uint()

    local is_sack = bit.band(bit.rshift(flags, 7), 1) == 1
    local is_up   = bit.band(bit.rshift(flags, 6), 1) == 1
    local ack     = bit.band(bit.rshift(flags, 5), 1) == 1
    local syn     = bit.band(bit.rshift(flags, 4), 1) == 1
    local fin     = bit.band(bit.rshift(flags, 3), 1) == 1
    local err     = bit.band(flags, 0x07)

    local payload_len = len - HEADER_SIZE

    -- Mismo formato que Packet.__str__ del codigo Python
    pinfo.cols.info = string.format(
        "[SN=%d,ACKN=%d,(TY=%s,OP=%s,ACK=%d,SYN=%d,FIN=%d,ERR=%d)] Len=%d",
        seq, ackn,
        is_sack and "SACK" or "SAW",
        is_up and "U" or "D",
        ack and 1 or 0, syn and 1 or 0, fin and 1 or 0, err,
        payload_len)

    local subtree = tree:add(rdt, buffer(), "SAW Protocol")
    subtree:add(f.seq, buffer(0, 1))
    subtree:add(f.ack_num, buffer(1, 1))

    local ftree = subtree:add(f.flags, buffer(2, 1))
    ftree:add(f.f_type, buffer(2, 1))
    ftree:add(f.f_op, buffer(2, 1))
    ftree:add(f.f_ack, buffer(2, 1))
    ftree:add(f.f_syn, buffer(2, 1))
    ftree:add(f.f_fin, buffer(2, 1))
    local e = ftree:add(f.f_error, buffer(2, 1))


    if payload_len > 0 then
        local payload = buffer(HEADER_SIZE, payload_len)

        if syn and is_up and not ack then
            -- file_size (3 bytes) + fn_len (1 byte) + file_name
            local ptree = subtree:add(rdt, payload, "SYN Upload Message")
            if payload_len >= 4 then
                local fn_len = payload(3, 1):uint()
                ptree:add(f.file_size, payload(0, 3))
                ptree:add(f.fn_len, payload(3, 1))
                if payload_len >= 4 + fn_len then
                    local name = payload(4, fn_len)
                    ptree:add(f.file_name, name)
                    pinfo.cols.info:append(string.format(
                        " UPLOAD \"%s\" (%d bytes)", name:string(), payload(0, 3):uint()))
                end
            end
        else
            subtree:add(f.payload, payload)
            subtree:add(f.payload_len, payload_len):set_generated()
        end
    end

    return len
end

local udp_table = DissectorTable.get("udp.port")
local registered_port = DEFAULT_PORT
udp_table:add(registered_port, rdt)

function rdt.prefs_changed()
    if registered_port ~= rdt.prefs.port then
        udp_table:remove(registered_port, rdt)
        registered_port = rdt.prefs.port
        udp_table:add(registered_port, rdt)
    end
end