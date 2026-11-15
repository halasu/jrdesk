# JRDesk icon generator (Pillow only). Usage: python make_icons.py <out_dir>
import os, sys
from PIL import Image, ImageDraw, ImageFont

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)
S = 512

def font(size):
    for p in [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

# gradient background (#0B3D91 -> #00A3C4, diagonal)
g = Image.new("RGBA", (S, S))
c1, c2 = (0x0B, 0x3D, 0x91), (0x00, 0xA3, 0xC4)
px = g.load()
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * (S - 1))
        px[x, y] = tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)) + (255,)
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([16, 16, 496, 496], radius=108, fill=255)
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
img.paste(g, (0, 0), mask)

d = ImageDraw.Draw(img)
W = (255, 255, 255, 255)
d.rounded_rectangle([83, 107, 429, 347], radius=34, outline=W, width=26)   # monitor
d.rectangle([226, 334, 286, 382], fill=W)                                   # stand
d.rounded_rectangle([166, 372, 346, 398], radius=13, fill=W)                # base
f = font(118)
d.text((256, 228), "JR", font=f, fill=W, anchor="mm")
cy = (0x7C, 0xF5, 0xFF)
d.arc([320, 88, 424, 192], start=270, end=360, fill=cy + (255,), width=18)  # signal arcs
d.arc([284, 52, 460, 228], start=270, end=360, fill=cy + (153,), width=18)

img.save(os.path.join(out, "icon-512.png"))
for s in (32, 64, 128, 256):
    img.resize((s, s), Image.LANCZOS).save(os.path.join(out, f"icon-{s}.png"))
img.save(os.path.join(out, "jrdesk.ico"),
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icons written to", out)
