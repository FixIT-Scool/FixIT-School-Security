```
+ -                                               ==FixIT Inc.==                                                  - +
|                                                                                                                   |
                             -_   Doc Volume 0x10, Issue 0x48, Phile #0x01 of 0x12   _-
 
  ,_,
 (.,.)
 (   )
 -"-"---pwn-|=----------------------------------------------------------------------------=|
            |=--------=[ FixIT-Scool is an application for schools and students ]=--------=|
            |=----------------------------------------------------------------------------=|
            |=-------------------=[ lol1074 but for you BitCrucio  ]=---------------------=|
            |=----------------------------------------------------------------------------=|
            |=----------------------------=[ FixIT-School ]=------------------------------=|            
|                                                                                                                    |
+ -                                                                                                                - +
``` 

---                                                                                 ---

```

--=[ Table of Contents:

  --< 1 => ::._Main_.::

      1.0 - Introduction
      1.1 -  Why does Dev exist ?
         1.1.1 - How to exploit this branch
      2.0 - Branching Strategy
         2.1 - Naming Conventions (feature/, bugfix/, hotfix/)
            2.2.1 - The Lifecycle of a PR

  --< 2 => .__-Security-__.

      1.0 - Policy and term
        1.1 - License
      2.0 - Vulnerability
        2.2 - Vulnerability Disclosure & Audit
       
```

---                                                                                 ---

```
--=[ 1.0: [ Introduction ]

     Developer.md is for developers, and anyone who wants to make changes or report bugs or improvements.
     Here you will find all the guidelines to do it,
     not only in a manner consistent with the policies in force in this repository but above all in a concise and cohesive way to facilitate,
     us in the resolution or addition of a function

     --=[ NOTE

           Having said that, for the sake of transparency,
           I would also like to point out that all the material in this repository is made by me,
           except for some things in the README.md, which are:

           -_-_-_  The ASCII-ART in the title of this .md file, the owl, \
                   You can download it from this link. I recommend it if you want to achieve the same result I did or if you'd like to explore more. \

                  --- [ > URL => < https://www.asciiart.eu/animals/birds-land > _-_-_-



--=[ 1.1: [ Why does Dev exist ? ]

     The < Dev > repo serves multiple reasons,
     both for the safety of end users and to keep the ready code separate from the code that is yet to be finalized.
     Below we will list the reasons for the presence of the repo and how to exploit it:

          --=[ 1: Protect code

               By setting a Filter Branch, we allow and guarantee that there are two phases of code verification before it can be put into production,
               both to limit bugs that are apparently invisible but also to avoid more sophisticated attacks such as supply chain attacks.

          --=[ 2: CI/CD & Automated Testing

               The Dev environment serves as a sandbox for continuous integration.
               Each commit triggers an automated test pipeline that validates the system's integrity without stressing the Main branch,
               ensuring that only functional code progresses to the release phase.

          --=[ 3: Experimental Freedom

               It allows developers to implement experimental features or structural refactoring in an isolated environment.
               This isolation prevents operational stability from being compromised and allows,
               for immediate rollback in the event of a critical failure, preserving service continuity.



          --=[ 1.1.1: [ How to exploit this branch ]

               The < dev > branch was specifically designed to be used by developers who want to actively contribute or not to the continuation and expansion of the features. Obviously,
               to ensure security and avoid unpleasant incidents, a filter branch was chosen as previously explained in section < 1.1 >. To use it, you are asked to make a pull request.
               Please specify exactly the changes or alterations to the original code and the reason why they were made.
               Furthermore, each pull will be supervised one by one before approval to determine its feasibility and reliability.

               --=[ NOTE

                    For those who are more curious about the process of modifications or additions within this project, we ask you to carefully read the following sections up to < 4.1 >.
                    For a better understanding of how your code will fall under the licenses and policies in force on this repository,
                    we ask you to also read the sections < Security 1.0> and < Security 1.1 >.


  
 --=[ 2.0: [ Branching Strategy ]

      This section explains how to actually enter code into dev.

      To understand how it is possible to add your own changes in Dev we must first talk about how the functions and their implementation are organized,
      in fact every function or bug fix and other things first pass through the specific branches and not through the actual Dev,
      which serves as a filter and also as a container for all the tests in a sandboxed way.

      --=[ example

+------------------------------------------------+
|                    START                       |
+------------------------------------------------+
                    |
                    v
        +---------------------------------+
        | Are you on the "dev" branch?    |
        +---------------------------------+
                    |
           +--------+--------+
           |                 |
         YES                NO
           |                 |
           v                 v
+----------------------+   +--------------------------------+
| CREATE NEW BRANCH    |   | CONTINUE ON BRANCH SUPPORTIVE  |
| from dev             |   +--------------------------------+ 
| (feature/* o bugfix/*|  
+----------------------+  
           |
           v
+----------------------------------------+
| git checkout dev                       |
| git pull origin dev                    | ---[ > // example commands
| git checkout -b feature/xxx            |
+----------------------------------------+
           |
           v
+----------------------------------------+
| MODIFICATION DEVELOPMENT               |
| - writing code                         |
| - local tests                          |
+----------------------------------------+
           |
           v
+----------------------------------------+
| COMMIT ON THE SUPPORT BRANCH           |
| git add .                              |
| git commit -m "description"            |
+----------------------------------------+
           |
           v
+----------------------------------------+
| REMOTE BRANCH PUSH                     |
| git push origin feature/xxx            |
+----------------------------------------+
           |
           v
+----------------------------------------+
| OPEN PULL REQUEST                      |
| FROM: feature/xxx                      |
| TO: dev                                |
+----------------------------------------+
           |
           v
+----------------------------------------+
| CODE REVIEW                            |
| - controls                             |
| - possible fix                         |
+----------------------------------------+
           |
           v
+-----------------------------+
| PR approved?                |
+-----------------------------+
           |
     +-----+-----+
     |           |
   NO          YES
     |           |______________ 
     v                          v
+----------------------+   +----------------------+
| apply corrections    |   | merge on dev         |
| or any changes       |   | (no direct commits)  |
+----------------------+   +----------------------+
                                 |
                                 v
                    +-----------------------------+
                    | FINISH                      |
                    +-----------------------------+


           --=[ 2.1: [ Naming Conventions (feature/, bugfix/, hotfix/) ]

                As illustrated in detail, there are different branches for different operations within the code.
                For this reason, we would like to explain which of these are actually present and what their purpose is.
                --=[ Legend
                    - [+] => Main 
                             Core branches used as integration points and testing containers, (e.g. dev).
                    - [/] => Supportive branches  
                             Temporary branches created from dev to develop features,
                             bug fixes, or improvements (feature/*, bugfix/*, hotfix/*).
                    - [-] => Restricted   
                             Branches where direct commits are not allowed and changes
                             can be introduced only via Pull Requests.


                    [+ && -] - MAIN:   Production-ready branch.
                    [+ && -] - Dev:    Integration and testing branch.
                    [/] - feature/*:   Used for the development of new features.
                    [/] - bugfix/*:    Used to fix bugs identified during development or testing.
                    [/] - hotfix/*:    Used for urgent fixes or vulnerability.


                --=[ 2.1.1: [ The Lifecycle of a PR ]

                     This section describes the complete lifecycle of a Pull Request (PR),
                     from its creation on a support branch to its final merge into dev.

                     1. PR Creation
                        A Pull Request is opened from a support branch (feature/*, bugfix/*, hotfix/*)
                        destined for the dev branch.

                     2. Initial Validation
                        The PR is automatically checked to ensure:
                             - that the source branch is updated with dev
                             - that naming conventions are respected
                             - that no direct commits are made to protected branches


                     After these phases, we move on to the code review. In fact, more or less a single code reviewer will analyze it for bugs that are not visible to local tests and for potential backdoors introduced into the code.
                     After ensuring that everything is OK and that all clauses and policies have been respected, the <PR> branch will be accepted and then moved to the <Dev> branch.



   --=[ Sec 1.0: [ Policy and term ]

            This section defines the security policies and terms that all contributors
            must follow when interacting with this repository. Compliance with these policies is mandatory
            to ensure integrity, traceability, and legal compliance.

            - You are required to comply with all the rules outlined above.
            - Please read the license in the readme.md file to learn how you can interact with the code.


       Compliance Requirements

            - All contributions must comply with these license terms.
            - Any security-related changes or reports must respect the repository's
              disclosure procedures.
            - Unauthorized modifications or violations of license terms can result in
              revocation of contributor privileges.

            NOTE:
                This policy establishes the legal and operational framework for all development
                activities in this repository. For specific security procedures, see sections
                on Secret Management, Detecting Sensitive Data Leaks, and Vulnerability Disclosure.


            --=[ Sec 2.0: [ License ]

                  The license is present in a complete and official way in the < README.md > where both the clauses and the rules to be followed are expressed.
                  For further information, you are asked to access the < LICENSE.md > file.
                  If you believe that some of these clauses are not suitable or you think that they are not good or there are errors/incompressions,
                  you can contact us at the email address.
                  (You can find the email in the < README.MD > file in the < 5.0 > section, specifically in Creator and other )



   --=[ Sec 2.1: [ Vulnerability ]

            FixIT-School takes security vulnerabilities very seriously, whether they could
            harm individuals or institutions, or cause service downtime. 
            Even though no schools currently use our software, we are committed to
            preserving the security and integrity of the service. 

            Below, we outline how to report vulnerabilities responsibly, as well as
            guidelines to prevent leaks or the exposure of private information.



            --=[ 2.2: [ Vulnerability Disclosure & Audit ]

                 Please do not open GitHub issues or pull requests - this makes the problem immediately visible to everyone, including malicious actors.
                 Security issues in this open source project can be safely reported via privately by means of the email indicated in the README.md in section 5.0 or
                 via github it is in fact possible to create a private area for security holes.
                 you can create a private area for security vulnerabilities. However,
                 if the vulnerability affects only a function or interaction present exclusively in the development environment or in one of the non-production branches,
                 it will still be possible to make it public, as it does not affect production systems.

                ---[ > Info 

                      - If the vulnerability affects production systems, it will not be possible to disclose it for the first two weeks.
                        This embargo is intended to allow time to implement a hotfix or other necessary mitigations.
                        Only after the solution has been adopted will it be possible to publicly disclose it.

                      - If the vulnerability is present only in test or development branches,
                        or in features not yet in production, it will be possible to disclose it publicly,
                        even via pull request, since it does not impact the systems in use by users.

                      - All vulnerabilities must be securely and privately reported to the project managers before public disclosure.
                        (e.g., via the email address listed in README.md or the private GitHub security area).
                        This allows for coordinated fixes and reduced risk to users.

                      - When disclosing a vulnerability (whether in production or test branches),
                        always provide a clear description, technical details, and reproduction steps.
                        Transparency helps other developers understand and effectively fix the issue.
 

```
