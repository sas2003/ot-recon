local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Probes B&R Automation web endpoints (System Diagnostics Manager, mapp View,
mapp Cockpit) for identifying content. Used by OT-Recon for vendor/device
fingerprinting when no dedicated industrial protocol (like S7 or EtherNet/IP)
is available.

This script does NOT attempt to probe B&R's proprietary PVI, ANSL, or
SafeDESIGNER protocols — no public spec exists for those, so only port-
signature evidence is used for them (handled in Python, not here).
]]

author = "OT-Recon Project"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap --script br-info -p 80,81,8084 <target>
--
-- @output
-- | br-info:
-- |   Vendor: B&R Automation
-- |   Component: System Diagnostics Manager (SDM) on port 80
-- |_  Title (/sdm): System Diagnostics Manager

-- Only run on the three ports where B&R exposes web interfaces.
portrule = shortport.port_or_service({80, 81, 8084}, {"http", "http-alt"})

local PROBES = {
    [80]   = {path = "/sdm",  component = "System Diagnostics Manager (SDM)"},
    [81]   = {path = "/",     component = "mapp View"},
    [8084] = {path = "/",     component = "mapp Cockpit"},
}

-- Strings whose presence in the response body confirms a B&R device.
local VENDOR_SIGNATURES = {"Bernecker", "B&R", "B%%26R"}

-- Strings that confirm specific B&R components.
local COMPONENT_SIGNATURES = {
    ["System Diagnostics Manager"] = true,
    ["SDM"]        = true,
    ["mapp View"]  = true,
    ["mapp Cockpit"] = true,
}

local function extract_title(body)
    local title = body:match("<[Tt][Ii][Tt][Ll][Ee]>(.-)</[Tt][Ii][Tt][Ll][Ee]>")
    if title then
        return title:match("^%s*(.-)%s*$")  -- trim whitespace
    end
    return nil
end

action = function(host, port)
    local probe = PROBES[port.number]
    if not probe then
        -- Fallback: if the port isn't in our map, try / anyway.
        probe = {path = "/", component = "Unknown"}
    end

    local response = http.get(host, port, probe.path)
    if not response or not response.body then
        return nil
    end

    local body = response.body
    local vendor_confirmed = false

    -- Check for vendor-identifying strings.
    for _, sig in ipairs(VENDOR_SIGNATURES) do
        if body:find(sig) then
            vendor_confirmed = true
            break
        end
    end

    -- Check for component-identifying strings.
    local component_confirmed = false
    for sig, _ in pairs(COMPONENT_SIGNATURES) do
        if body:find(sig, 1, true) then
            component_confirmed = true
            break
        end
    end

    -- Only produce output if we found at least one B&R indicator.
    if not vendor_confirmed and not component_confirmed then
        return nil
    end

    local output = {}

    if vendor_confirmed then
        table.insert(output, "Vendor: B&R Automation")
    end

    if component_confirmed then
        table.insert(output, ("Component: %s on port %d"):format(
            probe.component, port.number
        ))
    end

    local title = extract_title(body)
    if title and #title > 0 then
        table.insert(output, ("Title (%s): %s"):format(probe.path, title))
    end

    if #output > 0 then
        return stdnse.format_output(true, output)
    end

    return nil
end
