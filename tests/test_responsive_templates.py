import unittest
from pathlib import Path

from app import app


class ResponsiveTemplateTests(unittest.TestCase):
    def test_every_full_page_loads_responsive_styles_and_viewport(self):
        templates_dir = Path(app.template_folder)
        full_pages = []

        for template_path in templates_dir.glob("*.html"):
            markup = template_path.read_text(encoding="utf-8")
            if "</head>" not in markup.lower():
                continue

            full_pages.append(template_path.name)
            self.assertIn(
                "css/responsive.css",
                markup,
                f"{template_path.name} does not load the shared responsive stylesheet",
            )
            self.assertRegex(
                markup,
                r"""name=["']viewport["']""",
                f"{template_path.name} does not define a mobile viewport",
            )

        self.assertGreater(len(full_pages), 0)

    def test_all_templates_compile(self):
        for template_name in app.jinja_env.list_templates():
            with self.subTest(template=template_name):
                app.jinja_env.get_template(template_name)


if __name__ == "__main__":
    unittest.main()
