class TodoItem:
    def __init__(self, title, description, dt, task_id=0, is_completed=False):
        self.dt = dt
        self.task_id = task_id
        self.title = title
        self.description = description        
        self.is_completed = is_completed


    def to_dict(self):
        return {
            'task_id' : self.task_id,
            'dt' : self.dt,
            'title': self.title,
            'description': self.description,                       
            'is_completed': self.is_completed
        }