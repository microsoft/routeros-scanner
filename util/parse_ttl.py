def parse_ttl(s_ttl):
    if s_ttl.isdigit():
        return int(s_ttl)
    map =  {
        'd': 24 * 60 * 60,
        'h': 60 * 60,
        'm': 60,
        's': 1
    }
    ttl = 0
    input = s_ttl
    for key in map:
        parts = input.split(key, 1)
        if len(parts) == 2:
            ttl = ttl + (int(parts[0]) * map[key])
            input = parts[1]
    return ttl


if __name__ == '__main__':
    tests = {
        '1234': 1234,
        '1234s': 1234,
        '1d2h3m4s': 93784,
        '1h2m3s': 3723,
        '1m2s': 62,
        '1s': 1,
    }
    for input in tests:
        output = parse_ttl(input)
        print(f'Input: {input}\tOutput: {output}\nPassed: {output == tests[input]}\n')