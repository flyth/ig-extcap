ig = Proto("ig", "Inspektor Gadget")

k8s_pod_F           = ProtoField.string("ig.k8s.pod", "K8s Pod Name")
k8s_ns_F            = ProtoField.string("ig.k8s.ns", "K8s Namespace")
k8s_container_F     = ProtoField.string("ig.k8s.containerName", "K8s Container Name")
proc_comm_F         = ProtoField.string("ig.proc.comm", "Command")
runtime_container_F = ProtoField.string("ig.runtime.containerName", "Runtime Container Name")

ig.fields = { k8s_pod_F, k8s_ns_F, k8s_container_F, runtime_container_F, proc_comm_F }

-- Cache the field handle (fast path)
local if_desc_f = Field.new("frame.interface_description")

local packet_desc_f = Field.new("frame.comment")

-- Percent-decoder for query-string values (also converts '+' to space)
local function pct_decode(s)
  if not s then return nil end
  s = s:gsub("+", " ")
  s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
  return s
end

local function as_string(desc)
	local s
	if type(desc) == "userdata" or type(desc) == "table" then
		s = tostring(type(desc) == "table" and desc[1] or desc)
	else
		s = tostring(desc)
	end
	return s
end

-- Extract key=value pairs from a description string.
local function parse_if_desc(desc)
  if not desc or desc == "" then return nil, nil, nil, nil end

  -- Convert FieldInfo to string if needed
  local s = as_string(desc)
  if not s or s == "" then return nil, nil, nil, nil end

  local pod, ns, container, runtimeContainer

  -- Single pass: accept both ';' as separator
  -- Keys limited to [A-Za-z0-9_.], values capture until next ';'
  for k, v in s:gmatch("([%w_.]+)=([^;]*)") do
	if k == "k8s.podName" then
	  pod = pct_decode(v)
	elseif k == "k8s.ns" then
	  ns = pct_decode(v)
	elseif k == "k8s.containerName" then
	  container = pct_decode(v)
	elseif k == "runtime.containerName" then
		runtimeContainer = pct_decode(v)
	end
  end

  return pod, ns, container, runtimeContainer
end

-- Extract key=value pairs from a description string.
local function parse_packet_desc(desc)
  if not desc or desc == "" then return nil end

  -- Convert FieldInfo to string if needed
  local s = as_string(desc)
  if not s or s == "" then return nil end

  local proc

  -- Single pass: accept both ';' as separator
  -- Keys limited to [A-Za-z0-9_.], values capture until next ';'
  for k, v in s:gmatch("([%w_.]+)=([^;]*)") do
	if k == "proc.comm" then
	  proc = pct_decode(v)
	end
  end

  return proc
end

function ig.dissector(buffer, pinfo, tree)
  local fi = if_desc_f()

  local pod, ns, container, runtimeContainer
  if fi then
	  pod, ns, container, runtimeContainer = parse_if_desc(fi)
  end

  local pd = packet_desc_f()

  local comm
  if pd then
   comm = parse_packet_desc(pd)
  end

  local igSubtree = tree:add(ig, "Inspektor Gadget")
  local k8sSubtree = igSubtree:add(ig, "Kubernetes")
  local runtimeSubtree = igSubtree:add(ig, "Runtime")
  local processSubtree = igSubtree:add(ig, "Process")
  if pod then k8sSubtree:add(k8s_pod_F, pod) end
  if ns then k8sSubtree:add(k8s_ns_F, ns) end
  if container then k8sSubtree:add(k8s_container_F, container) end
  if runtimeContainer then runtimeSubtree:add(runtime_container_F, runtimeContainer) end
  if comm then processSubtree:add(proc_comm_F, comm) end
end

register_postdissector(ig)
