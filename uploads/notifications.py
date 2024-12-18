from django.db import models
from .users import User

class Notification(models.Model):
    NotificationID = models.AutoField(primary_key=True)
    UserID = models.ForeignKey(User, on_delete=models.CASCADE)
    Title = models.CharField(max_length=250)
    Description = models.CharField(max_length=2000)
    Date = models.DateTimeField(auto_now_add=True)
    Open = models.BooleanField(default=False)