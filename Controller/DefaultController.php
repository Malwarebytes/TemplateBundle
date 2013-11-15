<?php

namespace Malwarebytes\TemplateBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Response;

class DefaultController extends Controller
{
    /**
     * @Route("/templates")
     * @Template()
     */
    public function listAction()
    {
        $catalog = $this->get('malwarebytes_template.catalog');

        $tnames = $catalog->getTemplates();

        $templates = array();
        foreach($tnames as $tname) {
            $route = $this->get('router')->generate('malwarebytes_template_default_template',
                array('template' => $tname)
            );
            $templates[] = "<a href='$route'>$tname</a><br>";
        }

        return array('templates' => $templates, 'topline' => 'Templates', 'title' => 'Templates');
    }

    /**
     * @Route("/template/{template}", requirements={"template" = ".+"})
     */
    public function templateAction($template)
    {
        $twig = $this->get('twig');

        return new Response($twig->render($template));
    }
}
