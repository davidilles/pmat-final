# WannaDefeat WannaCry?

## Practical Malware Analysis & Triage Course Final Blog Post

As part of my ongoing effort to continously learn something new (and hands-on) related to information security, I have recently completed the excellent course [Practical Malware Analysis & Triage](https://academy.tcm-sec.com/p/practical-malware-analysis-triage) offered by [TCM Security](https://academy.tcm-sec.com/) . The conclusion of this course is a final challenge that ask students to choose one of the malware samples covered during the course, write a triage report of the sample, write a set of detection (using [Yara](https://github.com/VirusTotal/yara)) rules for the sample,  and publish the findings. This post is my submission to satisfy this course closure requirement.

## The WannaCry Ransomware Cryptoworm

WannaCry is a ransomware cryptoworm, which targeted computers running the Microsoft Windows operating system by encrypting (locking) data and demanding ransom payments in the Bitcoin cryptocurrency. WannaCry surfaced as part of the The WannaCry ransomware attack in May 2017.  This attack was estimated to have affected more than 300,000 computers across 150 countries, with total damages ranging from hundreds of millions to billions of dollars. Security experts believed from preliminary evaluation of the worm that the attack originated from North Korea or agencies working for the country. 
(via: [Wikipedia](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)) 

## WannaWhy?

I have chosen WannaCry as the subject of my report for two reasons. First, it is a real-live malware that (to me at least) is more interesting to look at compared to lab-grown education specimen. Second, the WannaCry attack was famiously halted by [Marcus Hutchins](https://portswigger.net/daily-swig/marcus-hutchins-on-halting-the-wannacry-ransomware-attack-still-to-this-day-it-feels-like-it-was-all-a-weird-dream)  by identifying a "killswitch" in the malware, which story always fascinated me as some sort of "cyber-superhero" deed. 

## The Purpose of The Post

The purpose of this post, apart from satisfying the course requirement :) is to demistify how simple techniques (all covered in the course) can be used to identify WannaCry's killswitch and confirm that the killswitch is indeed real to showcase that these can simple techniques can be very effective even when applied to real, extremely destructive malware.

This post is not intended to provide a full analysis of the malware specimen, most notably its propagation mechanism is completely ignored by the analysis.




test image:

![](/_images/Pasted%20image%2020230217224923.png) 