<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_Extension;

class TemplateBundleExtension extends Twig_Extension
{
    public function getNodeVisitors()
    {
        return array(new CatalogerNodeVisitor());
    }

    public function getName()
    {
        return "malwarebytes_template";
    }
}