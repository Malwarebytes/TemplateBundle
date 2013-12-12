<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_Token;

class TemplateToken extends Twig_Token
{
    const COMMENT_TYPE = 12;

    public static function typeToString($type, $short = false)
    {
        if($type === self::COMMENT_TYPE) {
            $name = 'COMMENT_TYPE';
            return $short ? $name : 'Twig_Token::'.$name;
        } else {
            return parent::typeToString($type, $short);
        }
    }

    public static function typeToEnglish($type)
    {
        if($type === self::COMMENT_TYPE) {
            return 'comment string';
        } else {
            return parent::typeToEnglish($type);
        }
    }
}