   M S B A M L   `   `   `  ����G  CVersleutelen, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null+clr-namespace:VersleutelenVersleutelen  5   	       Versleutelen.MainWindow   5   	   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   ,localclr-namespace:Versleutelen     5   	   X TXceed.Wpf.Toolkit, Version=3.4.0.0, Culture=neutral, PublicKeyToken=3e4669d2f30244f44wpfx)http://schemas.xceed.com/wpf/xaml/toolkit  5   	     � Title$  Symmetric Encrypter��5   	   $	��543��6%   $
��1109��62    � WindowStartupLocation$ CenterScreen=�6?   $
��1109��6d   $	��543��6t   .��5	      � $��10,0,3.6,-0.4q�6   .+�5
   
   �� -   5         ��Name$ textboxLeft��5
      $
��Left=�6'   $��438.5��6B   $��	10,34,0,0q�6Q    �� TextWrapping$
 Wrap=�6d   $�� ��6x   $	��Top=�6�   $	��310��6�   " �� VerticalScrollBarVisibility$ Visible=�6�   �� 5   
   -   5        $ textboxRight��5      $
��Left=�6(   $��438.5��6C   $��
480,34,0,0q�6R   $
 Wrap=�6f   $�� ��6z   $	��Top=�6�   $	��310��6�   $ Visible=�6�   �� 5   
   -   5         ��Name$ buttonEncryption��5      $��
Encrypt =>��6+   $
��Left=�6@   $��325,136,0,0q�6[   $	��Top=�6p   $	��150��6�   $��76��6�   6�   �� 5   
   -   5        $ buttonDecryption��5      $��
<= Decrypt��6+   $
��Left=�6C   $��325,217,0,0q�6^   $	��Top=�6s   $	��150��6�   $��75��6�   6�   �� 5   
   -   5        $ buttonImportDecryptedFile��5      $��Import Decrypted File��64   $
��Left=�6T   $��	10,10,0,0q�6o   $	��Top=�6�   $	��200��6�   6�   �� 5   
   -   5        $ buttonImportEncryptedFile��5      $��Import Encrypted File��64   $
��Left=�6T   $��
590,10,0,0q�6o   $	��Top=�6�   $	��200��6�   6�   �� 5   
   -   5        $ buttonExportDecryptedFile��5      $��Export Decrypted File��64   $
��Left=�6T   $��
10,478,0,0q�6o   $	��Top=�6�   $	��200��6�   6�   �� 5   
   -   5        $ buttonExportEncryptedFile��5      $��Export Encrypted File��64   $
��Left=�6T   $��590,478,0,0q�6o   $	��Top=�6�   $	��200��6�   6�   �� 5   
   -	   5         ��Name$ labelKey��5      $��Encryption Key��6"   $
��Left=�6;   $��
795,34,0,0q�6V   $	��Top=�6j   $��90��6�   $��19��6�   $��1q�6�   �� 5   
   -
   5        $ textboxPublicKey��5      $
��Left=�6,   $	��135��6G   $��
795,53,0,0q�6T   $
 Wrap=�6h   $�� ��6|   $	��Top=�6�   $	��284��6�   $ Visible=�6�   �� 5   
   -   5        $ labelRandomKey��5      $��Random Key:��6(   $
��Left=�6>   $��795,193,0,0q�6Y   $	��Top=�6n   $��1q�6�   �� 5   
   -   5         ��Name$ checkboxRandomKey��5      $��Yes/ No��6.   $
��Left=�6@   $��795,216,0,0q�6[   $	��Top=�6p   �� 5   
   -   5        $ labelKeyLength��5      $��Key Length:��6(   $
��Left=�6>   $��795,236,0,0q�6Y   $	��Top=�6n   $��1q�6�   �� 5   
   -   5        $ textboxRandomKeyLength��5      $
��Left=�62   $��23��6M   $��795,259,0,0q�6Y   $
 Wrap=�6n   $�� ��6�   $	��Top=�6�   $��29��6�    J� RenderTransformOrigin$ 0.703,-1.426&�6�   	 �� 	MaxLength$	 3��6�   5      5      