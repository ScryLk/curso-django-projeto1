from django.urls import resolve, reverse
from recipes import views

from .test_recipe_base import RecipeTestBase


class RecipeSearchViewTest(RecipeTestBase):
    def test_recipe_search_uses_correct_view_function(self):
        resolved = resolve(reverse('recipes:search'))
        self.assertIs(resolved.func, views.search)

    def test_recipe_search_loads_correct_template(self):
        response = self.client.get(reverse('recipes:search') + '?q=teste')
        self.assertTemplateUsed(response, 'recipes/pages/search.html')

    def test_recipe_search_raises_404_if_no_search_term(self):
        url = reverse('recipes:search')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_recipe_search_term_is_on_page_title_and_escaped(self):
        url = reverse('recipes:search') + '?q=<Teste>'
        response = self.client.get(url)
        self.assertIn(
            "Search for &#x27;&lt;Teste&gt;&#x27;",
            response.content.decode('utf-8')
        )
    def test_recipe_search_can_find_recipe_by_title(self):
        title1 = "This is recipe one"
        title2 = "This is recipe two"
        recipe1 = self.make_recipe(
            slug='one',
            title=title1,
            author_data={'username': "one"}
        )
        recipe2 = self.make_recipe(
            slug='two',
            title=title2,
            author_data={'username': "two"}
        )
        search_url = reverse('recipes:search')

        response1 = self.client.get(f'{search_url}?q={title1}')
        self.assertIn(recipe1.title, response1.content.decode())

        response2 = self.client.get(f'{search_url}?q={title2}')
        self.assertIn(recipe2.title, response2.content.decode())

        response_both = self.client.get(f"{search_url}?q=this")
        self.assertIn(recipe1.title, response_both.content.decode())
        self.assertIn(recipe2.title, response_both.content.decode())
