"""
ANSI color helpers for CLI output (cross-platform via colorama).
"""
import os
import sys
from typing import NoReturn

try:
    import colorama
    colorama.init()
except ImportError:
    colorama = None  # type: ignore

# ── ANSI codes ──────────────────────────────────────────────────────
class _C:
    if colorama is None:
        RST = ''; BLD = ''; DIM = ''; INV = ''
        RED = ''; GRN = ''; YEL = ''; BLU = ''; MAG = ''; CYN = ''; WHT = ''
        LRED = ''; LGRN = ''; LYEL = ''; LBLU = ''; LMAG = ''; LCYN = ''
    else:
        RST = '\x1b[0m'; BLD = '\x1b[1m'; DIM = '\x1b[2m'; INV = '\x1b[7m'
        RED = '\x1b[31m'; GRN = '\x1b[32m'; YEL = '\x1b[33m'
        BLU = '\x1b[34m'; MAG = '\x1b[35m'; CYN = '\x1b[36m'; WHT = '\x1b[37m'
        LRED = '\x1b[91m'; LGRN = '\x1b[92m'; LYEL = '\x1b[93m'
        LBLU = '\x1b[94m'; LMAG = '\x1b[95m'; LCYN = '\x1b[96m'

C = _C()


# ── Helpers ─────────────────────────────────────────────────────────

def ok(text: str) -> str:
    return f'{C.GRN}{C.BLD}{text}{C.RST}'

def fail(text: str) -> str:
    return f'{C.RED}{C.BLD}{text}{C.RST}'

def warn(text: str) -> str:
    return f'{C.YEL}{C.BLD}{text}{C.RST}'

def info(text: str) -> str:
    return f'{C.BLU}{text}{C.RST}'

def dim(text: str) -> str:
    return f'{C.DIM}{text}{C.RST}'

def title(text: str) -> str:
    return f'{C.BLU}{C.BLD}{text}{C.RST}'

def head(text: str) -> str:
    return f'{C.BLD}{text}{C.RST}'

def data(text: str) -> str:
    return f'{C.WHT}{text}{C.RST}'

def brand(text: str) -> str:
    return f'{C.MAG}{C.BLD}{text}{C.RST}'

def value(text: str) -> str:
    return f'{C.LBLU}{text}{C.RST}'

def bool_yes(text: str = 'True') -> str:
    return ok(text)

def bool_no(text: str = 'False') -> str:
    return fail(text)


def status_bool(val: bool, yes: str = 'True', no: str = 'False') -> str:
    """Return colored boolean string."""
    return ok(yes) if val else fail(no)


def status_ok_fail(okay: bool, ok_text: str = 'OK', fail_text: str = 'FAILED') -> str:
    return ok(ok_text) if okay else fail(fail_text)


def colorize_line(text: str, *,
                  status_ok: bool = None,
                  is_title: bool = False,
                  is_warning: bool = False,
                  is_header: bool = False,
                  is_brand: bool = False,
                  is_data: bool = False,
                  is_section: bool = False) -> str:
    """Apply a preset color scheme to a whole line."""
    if is_title or is_header:
        return title(text)
    if is_brand:
        return brand(text)
    if is_warning:
        return warn(text)
    if is_section:
        return f'{C.MAG}{text}{C.RST}'
    if is_data:
        return data(text)
    if status_ok is True:
        return ok(text)
    if status_ok is False:
        return fail(text)
    return text


def cprint(*args, sep: str = ' ', end: str = '\n', **color_kw):
    """Print with color helpers: status_ok, is_title, is_warning, etc."""
    line = sep.join(str(a) for a in args)
    sys.stdout.write(colorize_line(line, **color_kw) + end)


def hr(char: str = '=', length: int = 60, color: str = None) -> str:
    line = char * length
    if color == 'cyan':
        return f'{C.BLU}{line}{C.RST}'
    if color == 'dim':
        return f'{C.DIM}{line}{C.RST}'
    return line
