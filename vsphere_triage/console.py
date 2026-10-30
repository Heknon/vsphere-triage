"""Reading a console screenshot without needing to see it.

The model reading these results may not accept images, so a screenshot is also
reduced to text: how much of it is black, whether two captures differ (frozen
or still working), whether it is dominated by a blue-screen colour, and, when
an OCR engine is installed, the words on it matched against the screens Windows
and Linux show while booting. Most of the fleet is Windows, from Vista up, whose
screens differ by generation; the phrases below cover both.
"""

from __future__ import annotations

import io
import shutil
from typing import Any

from PIL import Image, ImageChops, ImageStat

from vsphere_triage.vmlog import stop_codes

NEAR_BLACK = 16
# Grey level from which a pixel counts as light (text), and the share of such
# pixels on a black screen that means characters are shown.
BRIGHT = 160
TEXT_ON_BLACK_FRACTION = 0.0005
# The screen states a boot can show, by the words on them. Lower-case phrases.
SCREEN_STATES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "blue_screen",
        "Windows stopped with a blue screen",
        (
            "your pc ran into a problem",
            "your device ran into a problem",
            "stop code",
            "*** stop:",
            "a problem has been detected and windows has been shut down",
        ),
    ),
    (
        "boot_manager_error",
        "Windows Boot Manager could not start Windows",
        (
            "windows boot manager",
            "windows failed to start",
            "status: 0xc",
            "boot configuration data",
        ),
    ),
    (
        "no_boot_device",
        "the firmware found nothing to boot",
        (
            "no bootable device",
            "operating system not found",
            "pxe-e",
            "no boot device",
            "boot failed",
            "missing operating system",
        ),
    ),
    (
        "automatic_repair",
        "Windows is diagnosing or repairing itself",
        (
            "preparing automatic repair",
            "diagnosing your pc",
            "automatic repair",
            "startup repair",
        ),
    ),
    (
        "disk_check",
        "a disk check is running",
        (
            "scanning and repairing drive",
            "checking file system",
            "chkdsk",
            "repairing disk errors",
        ),
    ),
    (
        "windows_updating",
        "Windows is installing updates",
        (
            "working on updates",
            "configuring windows updates",
            "do not turn off your computer",
            "getting windows ready",
            "preparing windows",
            "installing update",
        ),
    ),
    ("device_setup", "Windows is setting up devices", ("getting devices ready", "setting up devices")),
    ("windows_starting", "Windows is still starting", ("starting windows", "windows is loading files")),
    (
        "windows_logon",
        "Windows reached the logon screen",
        (
            "press ctrl+alt+delete",
            "ctrl+alt+del",
            "other user",
            "sign in",
        ),
    ),
    ("linux_panic", "the Linux kernel panicked", ("kernel panic",)),
    (
        "linux_emergency",
        "Linux dropped to an emergency shell",
        ("emergency mode", "dracut", "give root password"),
    ),
    ("linux_login", "Linux reached a login prompt", ("login:",)),
    ("bootloader", "the bootloader is on screen", ("grub", "gnu grub", "boot loader")),
)


def analyse(data: bytes) -> dict[str, Any]:
    """What one PNG shows, as numbers: size, darkness, colour."""
    with Image.open(io.BytesIO(data)) as image:
        rgb = image.convert("RGB")
    gray = rgb.convert("L")
    histogram = gray.histogram()
    pixels = rgb.width * rgb.height or 1
    near_black = sum(histogram[:NEAR_BLACK]) / pixels
    # Light pixels on a dark screen are text: a text console or a login prompt is
    # over 98% black too, but unlike a dead screen it has characters on it.
    bright = sum(histogram[BRIGHT:]) / pixels
    small = rgb.resize((min(rgb.width, 200), min(rgb.height, 150)))
    classic = modern = 0
    raw = small.tobytes()
    for index in range(0, len(raw), 3):
        red, green, blue = raw[index], raw[index + 1], raw[index + 2]
        if blue > 130 and red < 40 and green < 40:  # noqa: PLR2004 - the Vista/7 navy
            classic += 1
        if blue > 150 and red < 60 and 80 < green < 160:  # noqa: PLR2004 - the 8/10/11 blue
            modern += 1
    count = small.width * small.height or 1
    return {
        "width": rgb.width,
        "height": rgb.height,
        "near_black_fraction": round(near_black, 4),
        "bright_fraction": round(bright, 5),
        "mean_brightness": round(ImageStat.Stat(gray).mean[0], 1),
        "blue_screen_colour_fraction": round(max(classic, modern) / count, 3),
    }


def difference(first: bytes, second: bytes) -> float:
    """Mean absolute difference between two screenshots, 0 to 255."""
    with Image.open(io.BytesIO(first)) as one, Image.open(io.BytesIO(second)) as two:
        a = one.convert("L")
        b = two.convert("L").resize(a.size)
    return round(ImageStat.Stat(ImageChops.difference(a, b)).mean[0], 2)


# A pixel this much brighter or darker has changed; a region this many pixels, and
# wider and taller than a text cursor, is something moving on screen.
CHANGED_PIXEL_LEVEL = 40
MOVING_PIXELS = 40
CURSOR_SIZE = 24


def moving_region(first: bytes, second: bytes) -> dict[str, Any] | None:
    """The box where two screenshots differ, if it is bigger than a blinking cursor.

    A boot or update spinner moves a few hundred pixels of a screen of hundreds of
    thousands: the mean difference stays near zero, so it alone reads a progressing
    boot as frozen. A blinking cursor changes too, but the guest need not be
    running for that, so a change no bigger than a cursor does not count.
    """
    with Image.open(io.BytesIO(first)) as one, Image.open(io.BytesIO(second)) as two:
        a = one.convert("L")
        b = two.convert("L").resize(a.size)
    mask = ImageChops.difference(a, b).point(lambda value: 255 if value >= CHANGED_PIXEL_LEVEL else 0)
    box = mask.getbbox()
    if box is None:
        return None
    changed = mask.histogram()[255]
    width, height = box[2] - box[0], box[3] - box[1]
    if changed < MOVING_PIXELS or (width <= CURSOR_SIZE and height <= CURSOR_SIZE):
        return None
    return {"changed_pixels": changed, "box": list(box)}


def ocr(data: bytes) -> tuple[str | None, str]:
    """The text on a screenshot, if an OCR engine is installed; why not, otherwise."""
    try:
        import pytesseract  # noqa: PLC0415 - optional, and absent on most hosts  # ty: ignore[unresolved-import]
    except ImportError:
        return None, "pytesseract is not installed"
    if shutil.which("tesseract") is None:
        return None, "the tesseract binary is not on PATH"
    try:
        with Image.open(io.BytesIO(data)) as image:
            return pytesseract.image_to_string(image.convert("L")), "tesseract"
    except Exception as error:  # noqa: BLE001 - a failed OCR loses the text, not the whole console read
        return None, f"OCR failed ({type(error).__name__}: {error})"


def screen_state(text: str) -> list[dict[str, str]]:
    """The boot screens whose words appear in OCR text, most serious first."""
    lowered = " ".join(text.lower().split())
    found = []
    for state, meaning, phrases in SCREEN_STATES:
        matched = next((phrase for phrase in phrases if phrase in lowered), None)
        if matched is not None:
            found.append({"state": state, "meaning": meaning, "matched": matched})
    return found


def read_captures(
    captures: list[bytes], *, black_fraction: float, frozen_difference: float
) -> dict[str, Any]:
    """Everything a sequence of screenshots says, in words, without the images."""
    analyses = [analyse(capture) for capture in captures]
    last = analyses[-1]
    findings = []
    result: dict[str, Any] = {"captures": len(captures), "analysis": analyses}
    if len(captures) > 1:
        change = difference(captures[0], captures[-1])
        moving = moving_region(captures[0], captures[-1])
        result["mean_difference"] = change
        result["moving_region"] = moving
        result["frozen"] = change < frozen_difference and moving is None
        findings.append(
            "the screen did not change between captures"
            if result["frozen"]
            else "the screen changed between captures: the guest is doing something"
        )
    black = last["near_black_fraction"] >= black_fraction
    text_on_black = black and last.get("bright_fraction", 0) >= TEXT_ON_BLACK_FRACTION
    result["black"] = black
    result["text_on_black"] = text_on_black
    if text_on_black:
        findings.append(
            "the screen is dark with text on it, not a blank display: on Linux a text console or "
            "login prompt; on Windows a boot error or the black stop-error screen of Windows 11 24H2+"
        )
    elif black:
        findings.append(
            "the screen is black: early boot before the display is set up, a hang, "
            "or a blanked display; the CPU and disk counters tell these apart"
        )
    result["blue_screen_colour"] = last["blue_screen_colour_fraction"] > 0.6  # noqa: PLR2004
    if result["blue_screen_colour"]:
        findings.append(
            "the screen is mostly Windows blue: a stop error, or the Windows Update or recovery "
            "screen, which use the same blue; the words on it (OCR) or a moving spinner tell them apart"
        )
    text, engine = ocr(captures[-1])
    result["ocr_engine"] = engine
    if text is not None:
        result["text"] = text.strip()[:2000]
        states = screen_state(text)
        result["screen_states"] = states
        codes = stop_codes(text)
        if codes:
            result["stop_codes"] = codes
        findings.extend(f"on screen: {item['meaning']} ({item['matched']!r})" for item in states)
    else:
        result["text"] = None
        findings.append(f"no OCR ({engine}); the words on the screen were not read")
    result["findings"] = findings
    return result
