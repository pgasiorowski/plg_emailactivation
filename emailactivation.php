<?php

/**
 * @package Email Activation
 * @author Piotr Gasiorowski
 * @copyright Copyright (c)2011-2013 Social Software Development
 * @license GNU General Public License version 2, or later
 */

// Protect from unauthorized access
defined('_JEXEC') or die('Restricted access');
defined('DS') or define('DS', DIRECTORY_SEPARATOR);

class plgUserEmailactivation extends JPlugin
{

    /**
     * Constructor
     *
     * @access      public
     * @param       object  $subject The object to observe
     * @param       array   $config  An array that holds the plugin configuration
     * @since       1.5
     */
    public function __construct(&$subject, $config)
    {

        parent::__construct($subject, $config);

        // TODO: apparently J1.5 has problem with loading default language
        /*
        $lang = JFactory::getLanguage();
        if (!empty($lang->_lang))
        {
            $path = JPATH_ADMINISTRATOR.DS.'language'.DS.$lang->_lang;
            $file = $path.DS.$lang->_lang.'.plg_user_emailactivation.ini';
    
            if (file_exists($file))
                $this->loadLanguage('', JPATH_ADMINISTRATOR, $lang->_lang);
            else
                $this->loadLanguage('', JPATH_ADMINISTRATOR, 'en-GB');
        }
        else
        {
            $this->loadLanguage();
        }
        */
        $this->loadLanguage();

        if (JRequest::getInt('emailactivation'))
        {
            $userId = JRequest::getInt('u');
            $app    = JFactory::getApplication();
            $user   = JFactory::getUser($userId);

            if ($user->guest)
            {
                // Undelegate wrong users and guests
                $app->redirect(JRoute::_(''));

            } else {

                $params = $user->getParameters();

                // get token from user parameters
                $token = $user->getParam('emailactivation_token');

                $token = md5($token);

                // check that the token is in a valid format.
                if (!empty($token) && strlen($token) === 32 && (int) JRequest::getVar($token, 0, 'get', 'integer')===1)
                {
                        // get user's new email from parameters
                        $email = $user->getParam('emailactivation');
                        $email_old    = $user->email;

                        if (!empty($email))
                        {
                            // remove token and old email from params
                            $user->setParam('emailactivation', null);
                            $user->setParam('emailactivation_token', null);

                            // load & store user table                    
                            $table = JTable::getInstance('user', 'JTable');
                            $table->load($userId);
                            $table->params = $params->toString();
                            $table->email = $email;
                            // $table->activation = '';

                            if($this->params->get('block', null)) {
                                // block user account
                                $table->block = 0;
                            }
    
                            // save user data
                            if(!$table->store())
                            {
                                throw new RuntimeException($table->getError());
                            }
                            else
                            {
                                $user->email = $email;

                                $app->enqueueMessage(JText::_('PLG_EMAILACTIVATION_ACTIVATED'));

                                $this->_emailChanged($user, $email_old, $email);

                                // Reirect afterwords
                                $app->redirect(JRoute::_($this->params->get('redirect_url', '')), false);
                            }
                        }

                } else jexit('Invalid Token');
            }
        }
    }

	/**
	 * @since	1.5
	 */
	public function onUserBeforeSave($user, $isnew, $new = array())
	{
		$this->onBeforeStoreUser($user, $isnew, $new);
	}

	/**
	 * @since	1.5
	 */
	public function onUserAfterSave($user, $isnew, $result, $error)
	{
		$this->onAfterStoreUser($user, $isnew, $result, $error);
	}

    /**
     * @since    1.6
     */
    public function onBeforeStoreUser($user, $isnew, $new = array())
    {
        // check whether we are going to update user's email
        if ($isnew || !isset($user['email']) || $user['email'] == $new['email'])
            return;

        $me = JFactory::getUser();

        // super admins can do everything
        if ($me->authorise('core.admin'))
        {
            $this->_emailChanged($user, $user['email'], $new['email']);
            return;  // J1.6+
        }

        // exclude from activating selected groups
        if ((int) $user['id'] === (int) $me->id)
        {
            // get user groups
            $userGroups = (isset($me->gid))? array($me->gid) : $me->groups;
            $allowedGroups = $this->params->get('groups', array());

            // if( count(array_intersect($userGroups, $allowedGroups)) > 0) return;

            // fix for the above
            if (!empty($userGroups) && !empty($allowedGroups) && is_array($userGroups) && is_array($allowedGroups))
            {
                foreach($userGroups as $userGroup)
                {
                    if(in_array($userGroup, $allowedGroups))
                    {
                        $this->_emailChanged($user, $user['email'], $new['email']);
                        return;
                    }
                }
            }
        }

        // save old email in session
        $session = JFactory::getSession();
        $session->set('emailactivation.old', $user['email']);
    }


    /**
     * @since    1.6
     */
    public function onAfterStoreUser($new, $isnew, $result, $error)
    {

        $userId = (int) $new['id'];
        $user = JFactory::getUser($userId);

        if (!isset($new['email']))
            return;

        // get old email from session
        $session = JFactory::getSession();
        $old = $session->get('emailactivation.old', null);

        if (empty($old))
            return;

        $sending = false;

        $app = JFactory::getApplication();

        // if saving user's data was successful
        if ($result && !$error)
        {
            // JomSocial  Fix
            $jsocial = false;
            $queue = $app->getMessageQueue();

            if (!empty($queue))
            {
                foreach($queue as $msg)
                {
                    if (isset($msg['message']) && strpos($msg['message'], $new['email']) > 1 )
                    {
                        $jsocial = true;
                        break;
                    }
                }
            }

            if ($jsocial)
                $activation = $user->getParam('emailactivation_token');
            else
                $activation = md5(mt_rand());

            // get the user and store new email in User's Parameters
            $user->setParam('emailactivation', $new['email']);
            $user->setParam('emailactivation_token', $activation);
            $user->email = $old;

            // get the raw User Parameters
            $params = $user->getParameters();

            // force old email until new one is activated
            $table = JTable::getInstance('user', 'JTable');
            $table->load($userId);
            $table->params = $params->toString();
            $table->email = $old;

            // block user account
            if ($this->params->get('block', null))
                $table->block = 1;
            // return; // to prevent save

            // save user data
            if (!$table->store())
                throw new RuntimeException($table->getError());

            if($jsocial)
                return;

            // store activation in session
            $user->setParam('emailactivation_token', $activation);

            // Send activation email
            if ($this->sendActivationEmail($user->getProperties(), $activation, $new['email']))
            {
                $app->enqueueMessage(JText::sprintf('PLG_EMAILACTIVATION_SENT', htmlspecialchars($new['email'])));

                // force user logout
                if ($this->params->get('logout', null) && $userId === (int) JFactory::getUser()->id)
                {
                        $app->logout();
                        $app->redirect(JRoute::_(''), false);
                }
            }
        }

        // clear session and return
        $session->set('emailactivation.old', null);

        return;
    }


    /**
     * Send activation email to user in order to proof it
     *
     * @access      private
     * @param       array   $data  JUser Properties ($user->getProperties)
     * @param       string  $token  Activation token 
     * @param       string  $email  New Email address
     * @since       1.0.2
     */
    private function sendActivationEmail($data, $token, $email)
    {
        $userID = (int) $data['id'];
        $data['siteurl'] = rtrim(JURI::root(), '/').'/index.php?option=com_users&task=edit&emailactivation=1&u='.$userID.'&'.md5($token).'=1';

        // Compile the user activated notification mail values.
        $config = JFactory::getConfig();
        $mailer = JFactory::getMailer();

        $emailSubject    = JText::sprintf(
            'PLG_EMAILACTIVATION_SUBJECT',
            $data['name'],
            $config->get('sitename')
        );

        $emailBody = JText::sprintf(
            'PLG_EMAILACTIVATION_BODY',
            $data['name'],
            $config->get('sitename'),
            $data['siteurl']
        );

        $mailer->setSender(array($config->get('mailfrom'), $config->get('fromname')));
        $mailer->addRecipient($email);
        $mailer->setSubject($emailSubject);
        $mailer->setBody($emailBody);
        
        if ($mailer->Send() !== true)
        {
            $app = JFactory::getApplication();
            $app->enqueueMessage(JText::_('PLG_EMAILACTIVATION_FAILED').': '.$send->message, 'error');
            return false;
        }

        return true;
    }

    /**
     * Event handler triggered when email got finally changed
     *
     * @access      private
     * @param       mixed   $user        JUser Object/Array
     * @param       string  $oldEmail    Old email 
     * @param       string  $email       New email
     * @since       1.3.0
     */
    private function _emailChanged($user, $oldEmail, $email)
    {
        $exec = trim($this->params->get('exec', null));

        if (!empty($exec))
        {
            // Convert to array 
            $user = is_object($user) ? get_object_vars($user) : $user;

            eval($exec);
        }
    }
}
