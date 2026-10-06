-- Disector de Wireshark para el protocolo RDT (SACK / Selective Repeat)
-- Mismo header de 3 bytes que saw.lua (Seq, Ack, Flags), pero interpreta
-- el payload segun el protocolo SACK:
--   * SYN  UPLOAD   -> MessageSynUpload   (file_size[3] + fn_len[1] + file_name)
--   * SYN  DOWNLOAD -> MessageSynDownload (fn_len[1] + file_name)
--   * SYN+ACK DOWNLOAD -> MessageSynAckDownload (file_size[3])
--   * ACK (sin SYN/FIN) con payload -> SackPayload (N[1] + N * (start[1], end[1]))
--   * resto -> datos del archivo
--
-- Uso: wireshark -X lua_script:sack.lua
-- o copiarlo a ~/.local/lib/wireshark/plugins/ y reiniciar Wireshark.
-- El puerto UDP se cambia en Edit > Preferences > Protocols > SACK.
-- Este script distingue SAW y SACK por el bit 7 del byte de flags, asi que
-- reemplaza a saw.lua: NO cargues los dos a la vez en el mismo puerto
-- (se pisan y gana el ultimo en cargarse). Saca saw.lua del directorio de plugins.

local rdt = Proto("SACK", "SACK Protocol")

local DEFAULT_PORT = 5000
local HEADER_SIZE = 3
local MAX_SEQ = 256

rdt.prefs.port = Pref.uint("UDP port", DEFAULT_PORT, "Puerto UDP del servidor SACK")

local type_names = { [0] = "Stop and Wait", [1] = "SACK" }
local op_names   = { [0] = "DOWNLOAD", [1] = "UPLOAD" }
local err_names  = {
    [0] = "Sin error",
    [1] = "Nombre de archivo invalido",
    [2] = "El archivo ya existe en el servidor",
    [3] = "El archivo es demasiado grande",
    [4] = "El archivo no existe en el servidor",
    [7] = "Error inesperado en el servidor",
}
local bool_names = { "Set", "Not set" }

local f = rdt.fields
f.seq     = ProtoField.uint8("sack.seq", "Sequence Number", base.DEC)
f.ack_num = ProtoField.uint8("sack.ack_num", "Ack Number", base.DEC)
f.flags   = ProtoField.uint8("sack.flags", "Flags", base.HEX)
f.f_type  = ProtoField.uint8("sack.flags.type", "Tipo", base.DEC, type_names, 0x80)
f.f_op    = ProtoField.uint8("sack.flags.op", "Operacion", base.DEC, op_names, 0x40)
f.f_ack   = ProtoField.bool("sack.flags.ack", "ACK", 8, bool_names, 0x20)
f.f_syn   = ProtoField.bool("sack.flags.syn", "SYN", 8, bool_names, 0x10)
f.f_fin   = ProtoField.bool("sack.flags.fin", "FIN", 8, bool_names, 0x08)
f.f_error = ProtoField.uint8("sack.flags.error", "Codigo de error", base.DEC, err_names, 0x07)

f.payload     = ProtoField.bytes("sack.payload", "Payload")
f.payload_len = ProtoField.uint32("sack.payload_len", "Largo del payload", base.DEC)

-- MessageSynUpload / MessageSynDownload / MessageSynAckDownload
f.file_size = ProtoField.uint24("sack.syn.file_size", "Tamano del archivo (bytes)", base.DEC)
f.fn_len    = ProtoField.uint8("sack.syn.file_name_len", "Largo del nombre", base.DEC)
f.file_name = ProtoField.string("sack.syn.file_name", "Nombre del archivo")

-- SackPayload
f.sack_count = ProtoField.uint8("sack.sack.count", "Cantidad de bloques SACK", base.DEC)
f.blk_start  = ProtoField.uint8("sack.sack.block.start", "Inicio", base.DEC)
f.blk_end    = ProtoField.uint8("sack.sack.block.end", "Fin", base.DEC)
f.blk_len    = ProtoField.uint16("sack.sack.block.len", "Paquetes en el bloque", base.DEC)

-- Datos de archivo
f.data     = ProtoField.bytes("sack.data", "Datos del archivo")
f.data_len = ProtoField.uint32("sack.data_len", "Bytes de datos", base.DEC)

-- Nombre corto para mostrar en la columna Info
local function kind_of(syn, ack, fin, is_up)
    if syn and ack then return "SYN-ACK" end
    if syn then return "SYN" end
    if fin and ack then return "FIN-ACK" end
    if fin then return "FIN" end
    if ack then return "ACK" end
    return "DATA"
end


function rdt.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len < HEADER_SIZE then return 0 end

    local seq   = buffer(0, 1):uint()
    local ackn  = buffer(1, 1):uint()
    local flags = buffer(2, 1):uint()

    local is_sack = bit.band(bit.rshift(flags, 7), 1) == 1
    local is_up   = bit.band(bit.rshift(flags, 6), 1) == 1
    local ack     = bit.band(bit.rshift(flags, 5), 1) == 1
    local syn     = bit.band(bit.rshift(flags, 4), 1) == 1
    local fin     = bit.band(bit.rshift(flags, 3), 1) == 1
    local err     = bit.band(flags, 0x07)

    pinfo.cols.protocol = is_sack and "SACK" or "SAW"

    local payload_len = len - HEADER_SIZE
    local kind = kind_of(syn, ack, fin, is_up)

    -- Mismo formato que Packet.__str__ del codigo Python
    pinfo.cols.info = string.format(
        "%s [SN=%d,ACKN=%d,(TY=%s,OP=%s,ACK=%d,SYN=%d,FIN=%d,ERR=%d)] Len=%d",
        kind, seq, ackn,
        is_sack and "SACK" or "SAW",
        is_up and "U" or "D",
        ack and 1 or 0, syn and 1 or 0, fin and 1 or 0, err,
        payload_len)

    local subtree = tree:add(rdt, buffer(),
        (is_sack and "SACK" or "SAW") .. " Protocol (" .. kind .. ")")
    subtree:add(f.seq, buffer(0, 1))
    subtree:add(f.ack_num, buffer(1, 1))

    local ftree = subtree:add(f.flags, buffer(2, 1))
    ftree:add(f.f_type, buffer(2, 1))
    ftree:add(f.f_op, buffer(2, 1))
    ftree:add(f.f_ack, buffer(2, 1))
    ftree:add(f.f_syn, buffer(2, 1))
    ftree:add(f.f_fin, buffer(2, 1))
    ftree:add(f.f_error, buffer(2, 1))

    if err ~= 0 then
        pinfo.cols.info:append(string.format(" ERROR: %s", err_names[err] or "desconocido"))
    end

    if payload_len > 0 then
        local payload = buffer(HEADER_SIZE, payload_len)

        -- SYN de UPLOAD (cliente -> servidor): tamano + nombre
        if syn and not ack and is_up then
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

        -- SYN de DOWNLOAD (cliente -> servidor): solo nombre
        elseif syn and not ack and not is_up then
            local ptree = subtree:add(rdt, payload, "SYN Download Message")
            if payload_len >= 1 then
                local fn_len = payload(0, 1):uint()
                ptree:add(f.fn_len, payload(0, 1))
                if payload_len >= 1 + fn_len then
                    local name = payload(1, fn_len)
                    ptree:add(f.file_name, name)
                    pinfo.cols.info:append(string.format(" DOWNLOAD \"%s\"", name:string()))
                end
            end

        -- SYN-ACK de DOWNLOAD (servidor -> cliente): tamano del archivo
        elseif syn and ack and not is_up and payload_len >= 3 then
            local ptree = subtree:add(rdt, payload, "SYN-ACK Download Message")
            ptree:add(f.file_size, payload(0, 3))
            pinfo.cols.info:append(string.format(" (%d bytes)", payload(0, 3):uint()))

        -- ACK con informacion SACK: N + N pares (start, end)
        -- (solo si el paquete es SACK; en Stop and Wait los ACK no llevan bloques)
        elseif is_sack and ack and not syn and not fin
               and payload_len >= 1
               and payload_len >= 1 + 2 * payload(0, 1):uint() then
            local n = payload(0, 1):uint()
            local ptree = subtree:add(rdt, payload(0, 1 + 2 * n), "SACK Payload")
            ptree:add(f.sack_count, payload(0, 1))

            local parts = {}
            for i = 0, n - 1 do
                local off = 1 + 2 * i
                local s = payload(off, 1):uint()
                local e = payload(off + 1, 1):uint()
                local count = ((e - s) % MAX_SEQ) + 1
                local btree = ptree:add(rdt, payload(off, 2),
                    string.format("Bloque %d: [%d-%d] (%d paquete%s)",
                        i + 1, s, e, count, count == 1 and "" or "s"))
                btree:add(f.blk_start, payload(off, 1))
                btree:add(f.blk_end, payload(off + 1, 1))
                btree:add(f.blk_len, count):set_generated()
                parts[#parts + 1] = string.format("[%d-%d]", s, e)
            end

            if n > 0 then
                pinfo.cols.info:append(" SACK=" .. table.concat(parts, ""))
            else
                pinfo.cols.info:append(" SACK=[]")
            end

            -- Bytes sobrantes tras los bloques (no esperados)
            local used = 1 + 2 * n
            if payload_len > used then
                subtree:add(f.payload, payload(used, payload_len - used))
            end

        -- Resto: datos del archivo
        else
            subtree:add(f.data, payload)
            subtree:add(f.data_len, payload_len):set_generated()
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