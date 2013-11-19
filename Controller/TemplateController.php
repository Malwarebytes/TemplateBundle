<?php

namespace Malwarebytes\TemplateBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Response;

class TemplateController extends Controller
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
            $route = $this->get('router')->generate('malwarebytes_template_template_info',
                array('template' => $tname)
            );
            $templates[] = "<a href='$route'>$tname</a><br>";
        }

        return array('templates' => $templates, 'topline' => 'Templates', 'title' => 'Templates');
    }

    /**
     * @Route("template/info/{template}", requirements={"template" = ".+"})
     * @Template()
     */
    public function infoAction($template)
    {
        $catalog = $this->get('malwarebytes_template.catalog');

        $info = $catalog->getInfo($template);

        return array('template' => $info, 'topline' => "Info: $template", 'title' => "Template Info: $template");
    }

    /**
     * @Route("/template/show/{template}", requirements={"template" = ".+"})
     */
    public function showTemplateAction($template)
    {
        $twig = $this->get('twig');

        return new Response($twig->render($template));
    }
}
