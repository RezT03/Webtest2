import pytesseract
from PIL import Image, ImageEnhance, ImageFilter

def solve_captcha(image_path):
    img = Image.open(image_path)
    img = img.convert('L').filter(ImageFilter.MedianFilter())
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(2)
    text = pytesseract.image_to_string(img, config='--psm 6')
    try:
        return eval(text)
    except:
        return None

if __name__ == '__main__':
    import sys
    image = sys.argv[1]
    print(solve_captcha(image))