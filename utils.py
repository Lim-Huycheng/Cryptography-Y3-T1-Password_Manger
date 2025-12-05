

def wipe_bytearray(arr):
    try:
        if arr is None:
            return
        if isinstance(arr, bytearray):
            for i in range(len(arr)):
                arr[i] = 0
            # Try a second overwrite pass to reduce chance of remnants
            for i in range(len(arr)):
                arr[i] = 0
        # If it's bytes (immutable), try to get writable memory via ctypes
        elif isinstance(arr, (bytes, memoryview)):
            b = bytearray(arr)
            for i in range(len(b)):
                b[i] = 0
    except Exception:
        pass

def wipe_str_dict(data_dict):
    try:
        for k in list(data_dict.keys()):
            entry = data_dict[k]
            if isinstance(entry, dict):
                # Overwrite each sensitive field with a short string, then remove
                for key in ("email", "password"):
                    if key in entry:
                        val = entry[key]
                        try:
                            # Overwrite with same-length zeros string first (best-effort)
                            entry[key] = '\0' * len(val)
                        except Exception:
                            entry[key] = ''
                        # then replace with empty string and delete
                        entry[key] = ''
                # replace entire entry with empty dict
                data_dict[k] = {}
        # Clear the top-level dict
        data_dict.clear()
    except Exception:
        pass
