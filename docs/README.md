# Preparing a Delicious Dish of Compliance from a Chef "Meal Kit"

You can also find this published as a [Github Page](https://snohio.github.io/mealkit/)

## Description

Chef's Premium Content is delivered fresh to you with only the finest ingredients of code. Utilizing that premium audit and remediation content (as I like to call it "meal kit"), I will teach you how to create a wrapper of compliance to deliver to your systems to ensure persistence and validation. Utilizing this method will get you from sous to head chef in the shortest time possible.

In this 90 Minute Workshop, we are going to create a wrapper cookbook with the premium STIG (Security Technical Implementation Guides), understand and implement waivers, use the Chef Infra remediation wrapper with exceptions, and deliver the content to a provided Ubuntu and Windows server.

## Prerequisites

For this Workshop to participate and follow along, you will need:

* Your laptop with Chef Workstation installed
  * You should know how to configure your local credentials file and be able to knife to a new server / org.
* A personal GitHub account
* A basic knowledge of Chef and policyfiles.
* 7zip or the like for Windows to Untar

## What we are doing in this Workshop

> The idea of this workshop came from the work I did to create a new and updated Chef DEMO for Solution Architects to present to potential customers and existing customer base. What we are going to do is build three cookbook, one base cookbook, one compliance cookbook that holds just the STIG compliance profile(s) and one (really two) that contain the remediation content (and the wrapper for attributes to indicate which to apply or not apply.)

Other things we are going to learn in this workshop are:

* Integrating Compliance Profiles into cookbooks and use the Compliance Phase. This eliminates the need to have profiles stored in other places and us tokens to access those.
* Looking at output in Automate - Infrastructure and Compliance

Due to time constraints, we are only going to use the Ubuntu 20.04 content, but adding additional content and guarding for different platforms is relatively easy and repeatable.

## What you should know at the end of this workshop

* How to create a base cookbook with the Chef Client configuration.
* Taking a Compliance Profile and creating a cookbook for it to be used with Compliance Phase.
* Creating a Waiver file and push it out with a cookbook.
* Enable / Disable features of our Premium Remediation content.
* Utilizing policyfiles, apply the same cookbooks but trigger functions with an attribute.

We are going to run our cookbook in three modes, client only (or base), audit only, and enforcement mode. 

## Some information about Chef Premium Content (Disclaimer)

> NOTE: We are using and sharing Progress Chef proprietary content. This is for educational purposes only. Please do not use or share this content without proper authority. Please check with your Account Exec to verify that you are entitled to the Chef Premium Content. Typically if sold Chef with Inspec as a part of our Compliance Automate SKU, you would be entitled.

## My Setup

* Using my standard Azure demo build out, run the Terraform plan with 27 (3 x 9) Ubuntu 20.04 workstations. These will automatically be bootstrapped to the IT_DEVOPS org.
* [Automate Server](https://mealkit.azure.chef-demo.com/)
* Create 8 orgs for 8 attendees. Make up fun names.
  * Create a user for each of those orgs
  * Store the PEM key to be shared with each attendee.
  * Suggest to put all of this into the github repo that will be used for sharing the content.
* Re-bootstrap 24 nodes, 3 each, to those 8 orgs
* They should have workstation installed and ready to edit their credentials file to connect to the [lab environment](https://mealkit.azure.chef-demo.com)
* I might get fancy and create Automate Users and maybe Projects. We will at least use Filters to view our own systems.

## Steps

### Step 1

* Clone the full chef-repo with the framework needed at https://github.com/snohio/mealkit/ to your laptop.
* Put this in your ~/ folder (so ~/mealkit)
* Open this repo with VS Code (or another editor if you don't have VS Code)

### Step 2

Setup your local KNIFE access with the information on the [Assignments](./assignments.md) page.

* Update your credentials file. Add a new profile called `mealkit`.
* It will look something like:

```bash
# tandori
[tandori]
client_name = "tandori"
client_key = "~/mealkit/nothingtoseehere/tandori.pem"
chef_server_url = "https://mealkit.azure.chef-demo.com/organizations/tandori"
cookbook_path = ['~/mealkit/cookbooks']
``` 

> All of the credentials are in `~/mealkit/nothingtoseehere/credentials`. You can rename your existing file and put this in that same folder. On MacOS/Linux it is in `~/.chef/` and Windows in `~\AppData\Local\chef\.chef\`.

Set your default profile to that profile (meal name). `$env:CHEF_PROFILE = "tandori"` for example.

* To test, run `knife client list` and you should see two `node-linux-##` nodes and the validator.

#### PAUSE HERE FOR TROUBLESHOOTING

### Looking at the base cookbook

* We are going to walk through the Policyfiles that are pre-configured.
* Let's also update these to include your meal name assignment

### Download the Compliance Profile from Automate

* Log on to the [Mealkit Automate](https://mealkit.azure.chef-demo.com/) instance.
* Use your `meal name` as the user and `Cod3Can!` as the password.
* Go to the Compliance Tab
* Search for `Ubuntu 20.04`
* Click on **Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide CAT I Only**
* Click Download
* Open the file and we'll walk through the rest.

### Download and apply the Premium Content

Premium Content is shared on mostly monthly basis to customers who have subscribed, via email with links to download as in the example below:

![Premium Content Download](https://d34smkdb128qfi.cloudfront.net/images/cheflibraries/about/image-6.png?sfvrsn=35428f68_0)

This is covered in the Chef Blog Post [How to Setup Seamless Premium Content Delivery for Compliance Audits & Remediation](https://www.chef.io/blog/details/how-to-setup-seamless-premium-content-delivery-for-compliance-audits-remediation)

* Download the Premium Content from [here](https://butlersa.blob.core.windows.net/snohio/STIG_Ubuntu2004_v1_2_0_cookbook.tar)
* Untar these and put them directly in the `~/mealkit/cookbooks/` folder

> We are going to review the `remediation_stig_ubuntu2004_v1_2_0_wrapper\attributes\default.rb` file and look at what is `"enabled": "false"`

> 