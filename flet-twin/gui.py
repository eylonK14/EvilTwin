import flet as ft


class EvilTwin(ft.Column):
    def __init__(self):
        super().__init__()

        pass


def main(page: ft.Page):
    page.title = "ToDo App"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.scroll = ft.ScrollMode.ADAPTIVE

    # create app control and add it to the page
    page.add(EvilTwin())


if __name__ == "__main__":
    ft.app(target=main)
