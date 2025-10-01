using UnityEngine;
using UnityEngine.SceneManagement;

public class GameManager : Singleton<GameManager>
{
    private bool _isCursorLock;

    // 커서 고정 기능
    public void SetCursorLock()
    {
        Cursor.visible = _isCursorLock;
        Cursor.lockState = _isCursorLock ? CursorLockMode.None : CursorLockMode.Locked;
        _isCursorLock = !_isCursorLock;
    }

    protected override void OnSceneLoaded(Scene scene, LoadSceneMode mode)
    {
        
    }

    protected override void OnSceneUnloaded(Scene scene)
    {
        
    }
}
