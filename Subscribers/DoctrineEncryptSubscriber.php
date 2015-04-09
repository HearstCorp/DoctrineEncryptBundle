<?php

namespace VMelnik\DoctrineEncryptBundle\Subscribers;

use Doctrine\Common\EventManager;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\Common\Annotations\Reader;
use \Doctrine\ORM\EntityManager;
use Doctrine\ORM\Proxy\Proxy;
use \ReflectionClass;
use VMelnik\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use HRM\MainBundle\Entity\User;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Encryptor interface namespace
     */

    const ENCRYPTOR_INTERFACE_NS = 'VMelnik\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'VMelnik\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * Annotation reader
     *
     * @var Doctrine\Common\Annotations\Reader
     */
    private $annReader;

    /**
     * Register to avoid multi decode operations for one entity
     *
     * @var array
     */
    private $decodedRegistry = array();

    /**
     * @var array
     */
    private $elasticaSubscribers = null;

    /**
     * @var bool
     */
    private $elasticaDown = false;

    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param string $encryptorClass The encryptor class.  This can be empty if a service is being provided.
     * @param string $secretKey The secret key.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     */
    public function __construct(Reader $annReader, $encryptorClass, $secretKey, EncryptorInterface $service = null)
    {
        $this->annReader = $annReader;
        if($service instanceof EncryptorInterface) {
            $this->encryptor = $service;
        } else {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $secretKey);
        }
    }

    /**
     * Listen a prePersist lifecycle event. Checking and encrypt entities
     * which have @Encrypted annotation
     * @param LifecycleEventArgs $args
     */
    public function prePersist(LifecycleEventArgs $args)
    {
        $entity = $args->getEntity();
        $this->processFields($entity);
    }

    /**
     * Listen a preUpdate lifecycle event. Checking and encrypt entities fields
     * which have @Encrypted annotation. Using changesets to avoid preUpdate event
     * restrictions
     *
     * @param PreUpdateEventArgs $args
     */
    public function preUpdate(PreUpdateEventArgs $args)
    {
        $entity = $args->getEntity();
        $em = $args->getEntityManager();
        $uow = $em->getUnitOfWork();

        $reflectionClass = new ReflectionClass(
            $entity instanceof Proxy ? get_parent_class($entity) : get_class($entity)
        );
        $properties = $reflectionClass->getProperties();

        foreach($properties as $refProperty) {
            $propName = $refProperty->getName();

            if($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)
                && $args->hasChangedField($propName)
            ) {
                $args->setNewValue($propName, $this->encryptor->encrypt($args->getNewValue($propName)));
            }

            // now compute change set for nested entities if possible
            $propValue = null;

            if($refProperty->isPublic()) {
                $propValue = $entity->$propName;
            } else {
                $getter = 'get' . self::capitalize($propName);

                if(method_exists($entity, $getter)) {
                    $propValue = $entity->$getter();
                }
            }

            if($propValue instanceof Proxy) {
                $classMetadata = $em->getClassMetadata(get_class($propValue));
                $uow->computeChangeSet($classMetadata, $propValue);
            }
        }

        $changeSet = $uow->getEntityChangeSet($entity);
        $eventManager = $em->getEventManager();
        if ($this->changeSetBroken($changeSet)) {
            $uow->clearEntityChangeSet(spl_object_hash($entity));

            if (!$this->elasticaDown) {
                $this->turnElasticaSubscribers('remove', $eventManager);
                $this->elasticaDown = true;
            }
        } elseif ($this->elasticaDown) {
            $this->turnElasticaSubscribers('add', $eventManager);
            $this->elasticaDown = false;
        }
    }

    /**
     * @param LifecycleEventArgs $args
     */
    public function postUpdate(LifecycleEventArgs $args)
    {
        if ($this->elasticaDown) {
            $this->turnElasticaSubscribers('add', $args->getEntityManager()->getEventManager());
            $this->elasticaDown = false;
        }
    }

    /**
     * @param EventManager $eventManager
     * @return array
     */
    private function getElasticaSubscribers(EventManager $eventManager)
    {
        if ($this->elasticaSubscribers !== null) {
            return $this->elasticaSubscribers;
        } else {
            $this->elasticaSubscribers = [];
            foreach($eventManager->getListeners() as $event => $subscribers) {
                foreach($subscribers as $subscriber) {
                    if ($subscriber instanceof \FOS\ElasticaBundle\Doctrine\Listener) {
                        $this->elasticaSubscribers[] = $subscriber;
                    }
                }
            }
        }

        return $this->elasticaSubscribers;
    }

    private function turnElasticaSubscribers($action, EventManager $eventManager)
    {
        $method = $action . 'EventSubscriber';
        foreach ($this->getElasticaSubscribers($eventManager) as $subscriber) {
            $eventManager->$method($subscriber);
        }
    }

    /**
     * @param $changeSet
     * @return bool
     */
    private function changeSetBroken($changeSet)
    {
        foreach ($changeSet as $changes) {
            if ($changes[0] != $changes[1]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Listen a postLoad lifecycle event. Checking and decrypt entities
     * which have @Encrypted annotations
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args)
    {
        $entity = $args->getEntity();
        if(!$this->hasInDecodedRegistry($entity, $args->getEntityManager())) {
            if($this->processFields($entity, false)) {
                $this->addToDecodedRegistry($entity, $args->getEntityManager());
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     * @return Array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
    {
        return array(
            Events::prePersist,
            Events::preUpdate,
            Events::postLoad,
            Events::postUpdate
        );
    }

    /**
     * Capitalize string
     * @param string $word
     * @return string
     */
    public static function capitalize($word)
    {
        if(is_array($word)) {
            $word = $word[0];
        }

        return str_replace(' ', '', ucwords(str_replace(array('-', '_'), ' ', $word)));
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param object $entity Some doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     * @return bool
     * @throws \RuntimeException
     */
    private function processFields($entity, $isEncryptOperation = true)
    {
        $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';
        $reflectionClass = new ReflectionClass(
            $entity instanceof Proxy ? get_parent_class($entity) : get_class($entity)
        );
        $properties = $reflectionClass->getProperties();
        $withAnnotation = false;
        foreach($properties as $refProperty) {
            if($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                $withAnnotation = true;
                // we have annotation and if it decrypt operation, we must avoid duble decryption
                $propName = $refProperty->getName();
                if($refProperty->isPublic()) {
                    $entity->$propName = $this->encryptor->$encryptorMethod($refProperty->getValue());
                } else {
                    $methodName = self::capitalize($propName);
                    if($reflectionClass->hasMethod($getter = 'get' . $methodName) && $reflectionClass->hasMethod($setter = 'set' . $methodName)) {
                        $currentPropValue = $this->encryptor->$encryptorMethod($entity->$getter());
                        $entity->$setter($currentPropValue);
                    } else {
                        throw new \RuntimeException(sprintf("Property %s isn't public and doesn't has getter/setter"));
                    }
                }
            }
        }

        return $withAnnotation;
    }

    /**
     * Encryptor factory. Checks and create needed encryptor
     * @param string $classFullName Encryptor namespace and name
     * @param string $secretKey Secret key for encryptor
     * @return EncryptorInterface
     * @throws \RuntimeException
     */
    private function encryptorFactory($classFullName, $secretKey)
    {
        $refClass = new \ReflectionClass($classFullName);
        if($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
            return new $classFullName($secretKey);
        } else {
            throw new \RuntimeException('Encryptor must implements interface EncryptorInterface');
        }
    }

    /**
     * Check if we have entity in decoded registry
     * @param Object $entity Some doctrine entity
     * @param \Doctrine\ORM\EntityManager $em
     * @return boolean
     * @deprecated does not work properly
     */
    private function hasInDecodedRegistry($entity, EntityManager $em)
    {
        return false;

        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());

        return isset($this->decodedRegistry[$className][$entity->$getter()]);
    }

    /**
     * Adds entity to decoded registry
     * @param object $entity Some doctrine entity
     * @param \Doctrine\ORM\EntityManager $em
     * @deprecated does not work properly
     */
    private function addToDecodedRegistry($entity, EntityManager $em)
    {
        return;

        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());
        $this->decodedRegistry[$className][$entity->$getter()] = true;
    }

}
