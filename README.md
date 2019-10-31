# Lambda AWS Health Notification #

This is a function to send scheduled maintenance instance to sns

# Instruction
1. Create virtual environment to create separate python environment for this project
2. Install required packages
    ```bash
    pip install -r requirements.txt
    ```
3. Generate lambda deployment package
    ```bash
    zappa package production
    ```
    or
    ```bash
    zappa package production -o function.zip
    ```
4. Create lambda function with source from `function.zip`