import pytermgui as ptg

CONFIG = """
config:
    InputField:
        styles:
            prompt: dim italic
            cursor: '@72'
    Label:
        styles:
            value: dim bold

    Window:
        styles:
            border: '60'
            corner: '60'

    Container:
        styles:
            border: '96'
            corner: '96'
"""

with ptg.YamlLoader() as loader:
    loader.load(CONFIG)


def showDialog(manager, title, content):
    modal = ptg.Window(
        title,
        ptg.Label(content),
        ptg.Button("OK", onclick=lambda *_: manager.close()),
        box=ptg.boxes.DOUBLE,
    ).center()

    manager.add(modal)
    manager.focus(modal)


def login(manager):
    fields = {
        "Username": ptg.InputField("Username: ", placeholder="Username"),
        "Password": ptg.InputField(
            "Password: ", placeholder="Password", is_password=True
        ),
    }

    def handle_login(*_):
        username = fields["Username"].value
        password = fields["Password"].value

        # Code for login

        if username == "user" and password == "pass":
            showDialog(
                manager, "Login Success", "C: ValueXYZ\nEnvelope Contents: {...}\n"
            )
        else:
            showDialog(manager, "Login Failed", "Invalid username or password.")

    login_window = ptg.Window(
        "[bold]Login[/bold]",
        *fields.values(),
        ptg.Button("Login", onclick=handle_login),
        ptg.Button("Back", onclick=lambda *_: main_menu(manager)),
        box=ptg.boxes.SINGLE,
        width=40,
    )

    manager.add(login_window.center())
    manager.focus(login_window)


def signup(manager):
    fields = {
        "Username": ptg.InputField("Username: ", placeholder="Username"),
        "Password": ptg.InputField(
            "Password", placeholder="Password", is_password=True
        ),
    }

    def handle_signup(*_):
        # Code for signup

        showDialog(manager, "Signup Success", "Shared Key: KeyXYZ")

    signup_window = ptg.Window(
        "[bold]Signup[/bold]",
        *fields.values(),
        ptg.Button("Signup", onclick=handle_signup),
        ptg.Button("Back", onclick=lambda *_: main_menu(manager)),
        box=ptg.boxes.SINGLE,
        width=40,
    )

    manager.add(signup_window.center())
    manager.focus(signup_window)


def main_menu(manager):
    for window in manager._windows:
        window.close()

    menu = ptg.Window(
        ptg.Button("Login", onclick=lambda *_: login(manager)),
        ptg.Button("Sign Up", onclick=lambda *_: signup(manager)),
        ptg.Button("Quit", onclick=lambda *_: manager.stop()),
        box=ptg.boxes.SINGLE,
        width=30,
    )

    manager.add(menu.center())


def main():
    with ptg.WindowManager() as manager:
        main_menu(manager)


if __name__ == "__main__":
    main()
