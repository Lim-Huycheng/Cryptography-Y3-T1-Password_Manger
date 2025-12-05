def wipe_bytearray(arr):
    try:
        if arr is None:
            return
        if isinstance(arr, bytearray):
            for i in range(len(arr)):
                arr[i] = 0
            for i in range(len(arr)):
                arr[i] = 0
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
                for key in ("email", "password"):
                    if key in entry:
                        val = entry[key]
                        try:
                            entry[key] = '\0' * len(val)
                        except Exception:
                            entry[key] = ''
                        entry[key] = ''
                data_dict[k] = {}
        data_dict.clear()
    except Exception:
        pass
