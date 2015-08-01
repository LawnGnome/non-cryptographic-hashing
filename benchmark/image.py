from math import floor, sqrt
from PIL import Image, ImageColor

def draw(results):
    size = 512
    im = Image.new("RGB", (size, size), "white")

    norm = [0 for _ in range(size ** 2)]
    for result in results:
        norm[floor((size * size) * (result / (2 ** 32)))] += 1

    mx = 30 / sqrt(max(norm))
    def transform(idx, n):
        if n == 0:
            return (255, 255, 255)
        else:
            hue = floor(360 * (idx / size))
            lightness = 80 - floor(sqrt(n) * mx)
            return ImageColor.getrgb("hsl(%d, 100%%, %d%%)" % (hue, lightness))
    norm = [transform(i, n) for i, n in enumerate(norm)]

    im.putdata(norm)
    return im.rotate(270)
