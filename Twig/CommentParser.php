<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_Parser;
use Twig_ParserInterface;

class CommentParser extends Twig_Parser implements Twig_ParserInterface
{
    protected $annotationParser;

    public function setAnnotationParser($parser)
    {
        $this->annotationParser = $parser;
    }

    public function subparse($test, $dropNeedle = false)
    {
        $lineno = $this->getCurrentToken()->getLine();
        $rv = array();
        while (!$this->stream->isEOF()) {
            switch ($this->getCurrentToken()->getType()) {
                case TemplateToken::TEXT_TYPE:
                    $token = $this->stream->next();
                    $rv[] = new \Twig_Node_Text($token->getValue(), $token->getLine());
                    break;

                case TemplateToken::VAR_START_TYPE:
                    $token = $this->stream->next();
                    $expr = $this->expressionParser->parseExpression();
                    $this->stream->expect(TemplateToken::VAR_END_TYPE);
                    $rv[] = new \Twig_Node_Print($expr, $token->getLine());
                    break;

                case TemplateToken::BLOCK_START_TYPE:
                    $this->stream->next();
                    $token = $this->getCurrentToken();

                    if ($token->getType() !== TemplateToken::NAME_TYPE) {
                        throw new \Twig_Error_Syntax('A block must start with a tag name', $token->getLine(), $this->getFilename());
                    }

                    if (null !== $test && call_user_func($test, $token)) {
                        if ($dropNeedle) {
                            $this->stream->next();
                        }

                        if (1 === count($rv)) {
                            return $rv[0];
                        }

                        return new \Twig_Node($rv, array(), $lineno);
                    }

                    $subparser = $this->handlers->getTokenParser($token->getValue());
                    if (null === $subparser) {
                        if (null !== $test) {
                            $error = sprintf('Unexpected tag name "%s"', $token->getValue());
                            if (is_array($test) && isset($test[0]) && $test[0] instanceof Twig_TokenParserInterface) {
                                $error .= sprintf(' (expecting closing tag for the "%s" tag defined near line %s)', $test[0]->getTag(), $lineno);
                            }

                            throw new \Twig_Error_Syntax($error, $token->getLine(), $this->getFilename());
                        }

                        $message = sprintf('Unknown tag name "%s"', $token->getValue());
                        if ($alternatives = $this->env->computeAlternatives($token->getValue(), array_keys($this->env->getTags()))) {
                            $message = sprintf('%s. Did you mean "%s"', $message, implode('", "', $alternatives));
                        }

                        throw new \Twig_Error_Syntax($message, $token->getLine(), $this->getFilename());
                    }

                    $this->stream->next();

                    $node = $subparser->parse($token);
                    if (null !== $node) {
                        $rv[] = $node;
                    }
                    break;

                case TemplateToken::COMMENT_TYPE:
                    $token = $this->stream->next();
                    $text = $token->getValue();
                    $annotations = $this->annotationParser->parse($text);

                    foreach($annotations as $annotation) {
                        $node = new MetadataNode($token->getValue(), $token->getLine());
                        $node->setAttribute('annotation', $annotation);
                        $rv[] = $node;
                    }

                    break;

                default:
                    throw new \Twig_Error_Syntax('Lexer or parser ended up in unsupported state.', 0, $this->getFilename());
            }
        }

        if (1 === count($rv)) {
            return $rv[0];
        }

        return new \Twig_Node($rv, array(), $lineno);
    }
}