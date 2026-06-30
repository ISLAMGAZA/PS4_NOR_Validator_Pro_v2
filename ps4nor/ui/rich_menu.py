import sys, os, traceback
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

run_option_func = None


def safe_wrap(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        tb = traceback.format_exc()
        return f"Error: {e}\n{tb}"


class RichMenu:
    VERSION = "1.01"
    AUTHOR = "ISLAM JAMEL - WOLD WIDE BGA GROUP"

    def __init__(self):
        self.current_path = None

    def banner(self, error=None):
        console.clear()
        title = Text()
        title.append("PS4 NOR Validator Pro", style="bold cyan")
        title.append(f"  V {self.VERSION}", style="yellow")
        console.print(Panel(title, box=box.ASCII, border_style="cyan"))
        subtitle = Text("BY ISLAM JAMEL - WOLD WIDE BGA GROUP", style="bold green")
        console.print(subtitle, justify="center")
        disc = Text("Disclaimer: This tool is made by an enthusiast, not a professional programmer. Save your files before using this tool.", style="dim white")
        console.print(disc, justify="center")
        if error:
            console.print(error, style="bold red", justify="center")
        console.print("")

    def status_bar(self):
        status = Text()
        if self.current_path:
            status.append(f" Loaded: {os.path.basename(self.current_path)}", style="green")
            status.append(f"  |  ", style="dim")
        else:
            status.append(" No dump loaded", style="yellow")
        status.append(f"  [{datetime.now().strftime('%H:%M:%S')}]", style="dim")
        console.print(status, justify="right")

    def show(self):
        while True:
            self.banner()
            self.status_bar()
            console.print("")
            grid = Table.grid(padding=(0, 3))
            grid.add_column(justify="center", width=38)
            grid.add_column(justify="center", width=38)
            left_col = [
                ("[1]", "Validate", "green"),
                ("[A]", "Auto-Repair", "bright_green"),
                ("[2]", "Deep Refresh", "blue"),
                ("[3]", "Franken-Donor", "blue"),
                ("[4]", "NVS/CID Repair", "magenta"),
                ("[5]", "EAP Key Recovery", "magenta"),
                ("[6]", "MBR Generator", "yellow"),
                ("[7]", "NVS Generator", "yellow"),
            ]
            right_col = [
                ("[8]", "Toggle Flags", "cyan"),
                ("[9]", "Revert Assistant", "red"),
                ("[S]", "Syscon Tools", "red"),
                ("[T]", "Torus Patcher", "cyan"),
                ("[B]", "Batch Rename", "white"),
                ("[C]", "Multi-Compare", "white"),
                ("[10]", "Extract", "white"),
                ("[11]", "Compare Donor", "white"),
            ]
            bottom = [
                ("[12]", "NVS Hex Viewer", "white"),
                ("[13]", "Save", "white"),
                ("[14]", "Rescan", "white"),
                ("[15]", "Credits", "white"),
                ("[0]", "Exit", "bright_red"),
            ]
            for (lk, ll, lc), (rk, rl, rc) in zip(left_col, right_col):
                ltxt = Text()
                ltxt.append(lk, style=lc)
                ltxt.append(f" {ll}", style="bold")
                rtxt = Text()
                rtxt.append(rk, style=rc)
                rtxt.append(f" {rl}", style="bold")
                grid.add_row(ltxt, rtxt)
            sep = Text("-" * 76, style="dim")
            grid.add_row(sep, sep)
            for bk, bl, bc in bottom[:3]:
                ltxt = Text()
                ltxt.append(bk, style=bc)
                ltxt.append(f" {bl}", style="bold")
                grid.add_row(ltxt, Text())
            grid.add_row(sep, sep)
            bt = Text()
            bt.append(bottom[3][0], style=bottom[3][2])
            bt.append(f" {bottom[3][1]}", style="bold")
            be = Text()
            be.append(bottom[4][0], style=bottom[4][2])
            be.append(f" {bottom[4][1]}", style="bold")
            grid.add_row(bt, be)
            console.print(Panel(grid, title="[bold]Main Menu[/bold]", box=box.ASCII, border_style="bright_blue"))
            console.print("")
            choice = Prompt.ask("Choice", default="").strip().upper()
            if choice == "0":
                console.print("\n[bold yellow]Exiting... Goodbye![/bold yellow]")
                break
            if run_option_func and choice in ('1', 'A', '2', '3', '4', '5', '6', '7', '8', '9', 'S', 'T', '10', '11', '12', '13', '14', '15', 'B', 'C'):
                with console.status("[bold cyan]Processing...[/bold cyan]"):
                    result = safe_wrap(run_option_func, choice)
                if result:
                    console.print("")
                    console.print(Panel(result, title="[bold]Result[/bold]", box=box.ASCII, border_style="green"))
                    console.print("")
                    Prompt.ask("Press Enter to continue", default="")
