<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_Lexer;
use Twig_LexerInterface;
use Twig_Environment;

class CommentLexer extends Twig_Lexer implements Twig_LexerInterface
{
    protected function lexComment()
    {
        if (!preg_match($this->regexes['lex_comment'], $this->code, $match, PREG_OFFSET_CAPTURE, $this->cursor)) {
            throw new Twig_Error_Syntax('Unclosed comment', $this->lineno, $this->filename);
        }

        $rawcomment = substr($this->code, $this->cursor, $match[0][1] - $this->cursor).$match[0][0];
        $commenttext = trim(substr($rawcomment, 0, strlen($rawcomment) - 3));

        $this->pushToken(TemplateToken::COMMENT_TYPE, $commenttext);

        $this->moveCursor($rawcomment);
    }

    protected function pushToken($type, $value = '')
    {
        if (TemplateToken::TEXT_TYPE === $type && '' === $value) {
            return;
        }

        $this->tokens[] = new TemplateToken($type, $value, $this->lineno);
    }
}