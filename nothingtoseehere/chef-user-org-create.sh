chef-server-ctl user-create tandori tandori User tandori@chef.io tandori -f tandori.pem
chef-server-ctl user-create pizza pizza User pizza@chef.io pizza1 -f pizza.pem
chef-server-ctl user-create potpie potpie User potpie@chef.io potpie -f potpie.pem
chef-server-ctl user-create meatloaf meatloaf User meatloaf@chef.io meatloaf -f meatloaf.pem
chef-server-ctl user-create quesadilla quesadilla User quesadilla@chef.io quesadilla -f quesadilla.pem
chef-server-ctl user-create chili chili User chili@chef.io chili1 -f chili.pem
chef-server-ctl user-create casserole casserole User casserole@chef.io casserole -f casserole.pem
chef-server-ctl user-create sloppyjoe sloppyjoe User sloppyjoe@chef.io sloppyjoe -f sloppyjoe.pem
chef-server-ctl user-create potroast potroast User potroast@chef.io potroast -f potroast.pem
chef-server-ctl org-create tandori 'A Mealkit to make tandori' --association_user tandori -f tandori-validator.pem
chef-server-ctl org-create pizza 'A Mealkit to make pizza' --association_user pizza -f pizza-validator.pem
chef-server-ctl org-create potpie 'A Mealkit to make potpie' --association_user potpie -f potpie-validator.pem
chef-server-ctl org-create meatloaf 'A Mealkit to make meatloaf' --association_user meatloaf -f meatloaf-validator.pem
chef-server-ctl org-create quesadilla 'A Mealkit to make quesadilla' --association_user quesadilla -f quesadilla-validator.pem
chef-server-ctl org-create chili 'A Mealkit to make chili' --association_user chili -f chili-validator.pem
chef-server-ctl org-create casserole 'A Mealkit to make casserole' --association_user casserole -f casserole-validator.pem
chef-server-ctl org-create sloppyjoe 'A Mealkit to make sloppyjoe' --association_user sloppyjoe -f sloppyjoe-validator.pem
chef-server-ctl org-create potroast 'A Mealkit to make potroast' --association_user potroast -f potroast-validator.pem

