-- Execute the actual generated Lua using a small, bounds-checking Wireshark
-- API adapter. This checks generated control flow; it does not qualify the
-- adapter as a substitute for Wireshark integration testing.
local parser_path, hex = arg[1], arg[2]
local data = hex:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end)
local proto
local ranges = {}
base = { DEC = 10 }
function Proto(name, description)
    proto = {name = name, description = description}
    return proto
end
ProtoField = setmetatable({}, {__index = function(_, kind)
    return function(name) return {field = name, kind = kind} end
end})
DissectorTable = {get = function() return {add = function() end} end}
local Tree = {}
function Tree:add(field, range)
    if field.field then table.insert(ranges, range.start .. ":" .. range.length) end
    return self
end
Tree.add_le = Tree.add
function Tree:set_len(length) assert(length >= 0) end
local Range = {}
Range.__index = Range
function Range:bytes()
    local content = data:sub(self.start + 1, self.start + self.length)
    return {tohex = function() return (content:gsub(".", function(ch) return string.format("%02X", ch:byte()) end)) end}
end
local function number(range, little, signed)
    local value = 0
    for n = 1, range.length do
        local index = little and range.length - n + 1 or n
        value = value * 256 + data:byte(range.start + index)
    end
    if signed and value >= 2 ^ (range.length * 8 - 1) then value = value - 2 ^ (range.length * 8) end
    return value
end
function Range:uint() return number(self, false, false) end
function Range:le_uint() return number(self, true, false) end
function Range:int() return number(self, false, true) end
function Range:le_int() return number(self, true, true) end
local buffer = setmetatable({len = function() return #data end}, {__call = function(_, start, length)
    start = start or 0
    length = length or (#data - start)
    assert(start >= 0 and length >= 0 and start + length <= #data, "adapter: out-of-bounds buffer access")
    return setmetatable({start = start, length = length}, Range)
end})
-- A broken generated loop must fail this test promptly instead of hanging CI.
debug.sethook(function() error("adapter: instruction budget exceeded") end, "", 2000000)
local success, failure = pcall(function()
    assert(loadfile(parser_path))()
    proto.dissector(buffer, {cols = {}}, Tree)
end)
debug.sethook()
if success then print("OK " .. table.concat(ranges, ",")) else print("ERROR " .. tostring(failure)) end
