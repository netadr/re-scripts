# Tiny script to import results from FLARE's FLOSS tool (https://github.com/mandiant/flare-floss) into a Binary Ninja analysis database
import binaryninja

prompt = binaryninja.interaction.get_open_filename_input('Choose FLOSS output file', '*.json')

f = open(prompt, 'r')

json = json.load(f)

for string in json['strings']['decoded_strings']:
    addr = string['decoded_at']
    decoded = string['string']
    print(f"{addr:#X}: {decoded}")
    bv.set_comment_at(addr, decoded)
