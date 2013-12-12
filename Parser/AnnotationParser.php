<?php

namespace Malwarebytes\TemplateBundle\Parser;

use Doctrine\Common\Annotations\DocParser;

class AnnotationParser
{
    protected $parser;

    public function __construct()
    {
        $this->parser = new DocParser();
        $this->parser->addNamespace('Malwarebytes\TemplateBundle\Annotation');
    }

    public function parse($text)
    {
        return $this->parser->parse($text);
    }
}