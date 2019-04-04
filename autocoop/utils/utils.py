def print_region(addr_start, value, n_bytes):
    """
    Prints a memory region similar to hexdump

    :param addr_start: Starting address
    :param value: Memory region to print
    :param n_bytes: Number of bytes to print
    """
    as_hex = "{value:0>{align}x}".format(value=value, align=n_bytes*2)
    out_str = ""
    as_str = ""
    prev_byte = 0
    for n, current_byte in enumerate(as_hex):
        if n % 16 == 0:
            out_str += "    {}\n0x{:0>12x}    ".format(as_str, addr_start+n/2)
            as_str = ""
        if n%2 == 1:
            out_str += current_byte + " "
            as_str += chr(int(prev_byte+current_byte, 16))
        else:
            out_str += current_byte
            prev_byte = current_byte
    print out_str + "    " + as_str

def int_to_bytes(number, n_bytes):
    """
    Returns a bytestring for an integer

    :param number: Integer to convert
    :param n_bytes: Number of bytes to convert to
    :return: Bytestring representing integer
    """
    as_hex = "{value:0>{align}x}".format(value=number, align=n_bytes * 2)
    n = 2
    pairs = [as_hex[i:i+n] for i in range(0, len(as_hex), n)]
    bytearray = map(lambda x: chr(int(x, 16)), pairs)
    return "".join(bytearray)
