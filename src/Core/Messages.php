<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 30/03/2019
 * Time: 16:00
 */

namespace Crayner\Authenticate\Core;


class Messages
{
    /**
     * @var array
     */
    private $messages;

    /**
     * @return array
     */
    public function getMessages(): array
    {
        return $this->messages ?: [];
    }

    /**
     * @param array $messages
     * @return Messages
     */
    public function setMessages(array $messages): Messages
    {
        $this->messages = array_merge($this->getMessages(), $messages);
        return $this;
    }

    /**
     * @var string
     */
    private $translationDomain = 'validators';

    /**
     * @return string
     */
    public function getTranslationDomain(): string
    {
        return $this->translationDomain;
    }

    /**
     * @param string $translationDomain
     * @return Messages
     */
    public function setTranslationDomain(string $translationDomain): Messages
    {
        $this->translationDomain = $translationDomain;
        return $this;
    }

    /**
     * @param string $key
     * @return string
     */
    public function getMessage(string $key): string
    {
        return isset($this->getMessages()[$key]) ? $this->getMessages()[$key] : '' ;
    }
}