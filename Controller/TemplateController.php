<?php

namespace Malwarebytes\TemplateBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;
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
    public function infoAction($template, Request $request)
    {
        $catalog = $this->get('malwarebytes_template.catalog');

        $info = $catalog->getInfo($template);

        $form = $this->createForm('template', array('__template' => $template));

        $form->handleRequest($request);

        if($form->isValid()) {
            $data = $this->turnFormDataIntoTemplateData($form->getData());
            return $this->render($template, $data);
        } else {
            return array('template' => $info, 'topline' => "Info: $template", 'title' => "Template Info: $template", 'form' => $form->createView());
        }
    }

    /**
     * @Route("/template/show/{template}", requirements={"template" = ".+"})
     */
    public function showTemplateAction($template)
    {
        $twig = $this->get('twig');

        return new Response($twig->render($template));
    }

    protected function turnFormDataIntoTemplateData($data)
    {
        $fields = array();

        foreach($data as $name => $value) {
            if($name === '__template') {
                continue;
            }

            if(strpos($name, '-:-') !== false) {
                $pieces = explode('-:-', $name);
                $type = array_shift($pieces);
                $data = array_pop($pieces);

                if(strpos($value, '->') !== false) {
                    $call = substr($value, strpos($value, '->') + 2);
                    $value = substr($value, 0, strpos($value, '->'));

                    $matches = array();
                    preg_match("/\\(\\s*'([^']+)'\\s*\\)|\\(\\s*('([^']+)',\\s*)+'([^']+)'\\s*\\)/", $call, $matches);
                    if(count($matches > 0)) {
                        $params = array();
                        foreach($matches as $match) {
                            if( (strpos($match, "'") !== 0) && (strpos($match, "(") !== 0) && strlen($match) > 0) {
                                $params[] = $match;
                            }
                        }
                    }
                    $call = substr($call, 0, strpos($call, '(')); var_dump($call, $params);
                }

                switch($type) {
                    case 'service':
                        $service = $this->get($value);

                        if(isset($call)) {
                            $service = call_user_func_array(array($service, $call), $params);
                        }

                        $fields[$data] = $service;
                        break;

                    case 'form':
                        // placeholder

                        break;

                    default:
                        throw new \InvalidArgumentException('An invalid type of contents was provided for field "' . $name . '"');
                }

            } else {
                $steps = explode(':', $name);
                $point = &$fields;

                while(($item = array_shift($steps)) !== null) {
                    $member = (strpos($item, '---') === false) ? false : true;
                    if($member) {
                        $item = '---';
                    }

                    if(count($steps) == 0) {
                        if($member) {
                            $point[0] = $value;
                            $point[1] = $value;
                            $point[2] = $value;
                        } else {
                            $point[$item] = $value;
                        }
                    } elseif(isset($point[$item]) && is_array($point[$item])) {
                        $point = &$point[$item];
                    } elseif(!isset($point[$item])) {
                        $point[$item] = array();
                        $point = &$point[$item];
                    }
                }
            }
        }

        return $fields;
    }
}
