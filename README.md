# Cobalt Strike BOFs
Beacon object files I made to use with Cobalt Strike

- ntllRemap
  - Uses the Beacon API to obtain current process handle and retrieve handle for `ntdll`, then gets the module info for `ntdll` and determines the base address and size of the image, creates a new RWX section, unmaps `ntdll`, maps the new empty section to the base address of the original `ntdll` with RWX, copies `ntdll` into this secion, changes to RX, then closes the handle.
  - Don't use this. It'll crash your beacon lol.

