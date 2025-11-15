class MLServiceError(Exception):
    """
    Custom exception for ML Service related errors.
    """
    
    def __init__(self, message: str = "An error occurred in the ML Service"):
        self.message = message
        super().__init__(self.message)

