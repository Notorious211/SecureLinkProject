# SecureLinkProject
Projet CISI 4

Bon, cette application est destinée à réaliser une analyse exhaustive des sites internet. Lorsque l'utilisateur fournit le nom d'un site web, l'application débute par extraire les informations essentielles de ce site, y compris les retours d'utilisateurs. Ces derniers sont ensuite analysés afin de déceler si le sentiment général exprimé est positif ou négatif, ce qui aide à estimer la qualité perçue du site.

Simultanément, l'application recueille des données sur la visibilité du site sur Internet, en examinant notamment son classement dans les résultats de recherche et d'autres facteurs susceptibles d'influer sur son rayonnement et sa visibilité. Ces données sont présentées à l'utilisateur à travers une interface conviviale, fournissant un aperçu clair et précis de la qualité du site concerné. En somme, l'application offre un service d'évaluation complet des sites web, s'appuyant à la fois sur l'avis des utilisateurs et sur la visibilité du site sur Internet.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-Ma tâche est de créer une application capable de réaliser une analyse de site web à partir de son nom de domaine.
-Afin d'extraire les informations de la page web, j'emploierai le web scraping. Des bibliothèques sur Python existent déjà à cet effet.
-Concernant les avis, j'utiliserai une bibliothèque NLP pour analyser ceux présents sur le site.
-En ce qui concerne le référencement, bien qu'il existe plusieurs services tels que SEMRush, Ahrefs ou MOZ proposant des API pour récupérer des données de référencement, ceux-ci sont payants et ne correspondent donc pas à notre objectif. Par conséquent, je réaliserai une analyse de référencement basique, notamment en analysant les balises meta de la page, en vérifiant l'existence d'un fichier sitemap, et en contrôlant si le site utilise le protocole HTTPS, entre autres.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
==> Web Scraping : BeautifulSoup et Requests
Ces deux bibliothèques Python sont utiles pour le web scraping. Requests permet d'envoyer des requêtes HTTP afin d'obtenir le contenu HTML d'une page web. BeautifulSoup sert à analyser ce contenu HTML et à extraire les informations essentielles.

==> Analyse des avis : NLTK ou TextBlob
Ces deux bibliothèques sont utiles pour l'analyse de sentiment, qui est le processus permettant de déterminer si un avis est positif ou négatif.

==> Analyse de référencement : Analyse manuelle
De nombreux outils de SEO (Search Engine Optimization) sont payants. Pour une analyse de référencement gratuite, je peux réaliser une analyse manuelle en vérifiant certaines bonnes pratiques de SEO sur le site web. Par exemple, vérifiez si le site utilise HTTPS, s'il dispose d'un fichier sitemap, analysez les balises meta, regardez le temps de chargement du site, etc. je peux également utiliser la bibliothèque requests pour voir si le site renvoie des codes d'erreur HTTP.

==> Création d'une interface utilisateur : Flask
Flask est un micro-framework web pour Python que je peux l'utiliser pour créer une interface utilisateur simple où les utilisateurs peuvent entrer le nom d'un site web et obtenir les résultats de votre analyse.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Ainsi, diverses questions se posent :

-Comment devrais-je concevoir l'interface utilisateur de mon application web d'analyse de sites ? Faut-il que cette interface comporte uniquement un champ pour insérer le nom de domaine à analyser, ou devrais-je intégrer des fonctionnalités supplémentaires pour améliorer l'expérience utilisateur ? Si des fonctionnalités supplémentaires sont nécessaires, lesquelles seraient les plus pertinentes pour les utilisateurs de cette application ?

-Quels facteurs spécifiques devrais-je inclure dans mon analyse de référencement manuelle ? Par exemple, la présence de HTTPS, un fichier sitemap, les balises meta, etc.

-Comment devrais-je structurer le système de classification de l'application, en tenant compte des informations obtenues par le web scraping, l'analyse des avis et l'analyse de référencement manuelle ? Y a-t-il des critères spécifiques pour évaluer et pondérer ces informations afin de déterminer une note globale pour le site web analysé ? Si oui, pourriez-vous me donner des indications sur comment établir ces critères ?
