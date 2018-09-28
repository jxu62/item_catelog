Item Catelog
This is the third project for Udacity Full Stack Web Dev Nano Degree.
Author: Jiqing Xu

About
This is an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

Skilled Learned
Efficiently interacting with data is the backbone upon which performant web applications are built
Properly implementing authentication mechanisms and appropriately mapping HTTP methods to CRUD operations are core features of a properly secured web application

Instruction to use

1. Install Vagrant and VirtualBox

2. Clone the fullstack-nanodegree-vm repository. There is a catalog folder provided for you, but no files have been included. If a catalog folder does not exist, simply create your own inside of the vagrant folder.

3. Download the zip file of this project and unzip all content into the catalog folder

4. Go to Vagrant directory using Terminal/Shell/Bash

5. Launch the Vagrant VM: vagrant up

6. SSH into the Vagrant VM: vagrant ssh

7. Do a cd /vagrant

8. do a cd catalog

9. Setup application database python database_setup.py

10. Run application using python application.py

11. Access the application locally using http://localhost:5000

JSON endpoint:

/all/item/JSON - gives JSON about all the items, regardless of category with their basic information

/all/<int:category_id>/item/<int:catalog_item_id>/JSON - gives JSON about 1 specific item with its basic information

/all/category/JSON - gives JSON about all the categories

Additional Notes:

1. If anything does not work with vagrant up and vagrant ssh, please see instructions on:

2. This webpage uses bootstrap and if the style does not load, please follow instruction to install required components: https://getbootstrap.com/docs/3.3/getting-started/ 