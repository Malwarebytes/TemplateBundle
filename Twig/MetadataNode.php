<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_Node;
use Twig_NodeOutputInterface;
use Twig_Compiler;

class MetadataNode extends Twig_Node implements Twig_NodeOutputInterface
{
    public function __construct($data, $lineno)
    {
        parent::__construct(array(), array('data' => $data), $lineno);
    }

    public function compile(Twig_Compiler $compiler)
    {
        return;
    }
}