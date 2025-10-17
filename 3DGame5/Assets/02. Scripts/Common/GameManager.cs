using System.Collections;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;
using static Constants;

public class GameManager : Singleton<GameManager>
{
    [SerializeField] private GameObject playerPrefab;

    public Canvas Canvas => GetCanvas();

    public EGameState GameState { get; private set; }

    private GameObject _player;
    private bool _isCursorLock;

    // 커서 고정 기능
    public void SetCursorLock()
    {
        Cursor.visible = _isCursorLock;
        Cursor.lockState = _isCursorLock ? CursorLockMode.None : CursorLockMode.Locked;
        _isCursorLock = !_isCursorLock;
    }

    public void SetGameState(EGameState state)
    {
        if (state == EGameState.Pause)
        {
            _player.GetComponent<PlayerController>().SetState(EPlayerState.Idle);
        }

        GameState = state;
    }

    public void LoadScene(ESceneName sceneName)
    {
        StartCoroutine(LoadSceneAsync(sceneName));
    }

    private IEnumerator LoadSceneAsync(ESceneName sceneName)
    {
        // GameState = EGameState.Pause;
        SetGameState(EGameState.Pause);

        // 로딩 화면 띄우기
        var loadingPanelPrefab = Resources.Load<GameObject>("Loading Panel");
        var loadingPanelObject = Instantiate(loadingPanelPrefab, Canvas.transform);
        var loadingPanelController = loadingPanelObject.GetComponent<LoadingPanelController>();

        // 로딩 창 표시
        bool showDone = false;
        loadingPanelController.Show(() => showDone = true);
        yield return new WaitUntil(() => showDone);

        // 씬 로드 진행
        AsyncOperation asyncOperation = SceneManager.LoadSceneAsync(sceneName.ToString());
        asyncOperation.allowSceneActivation = false; // 로딩이 끝나면 바로 씬 이동하는 걸 꺼둠

        // 게이지 차는 거 표현
        while (asyncOperation.progress < 0.9f)
        {
            loadingPanelController.SetProgress(asyncOperation.progress);
            yield return null;
        }
        loadingPanelController.SetProgress(1f);
        asyncOperation.allowSceneActivation = true;

        bool hideDone = false;
        loadingPanelController.Hide(() => hideDone = true);
        yield return new WaitUntil(() => hideDone);

        Destroy(loadingPanelObject);
    }

    protected override void OnSceneLoaded(Scene scene, LoadSceneMode mode)
    {
        switch (scene.name)
        {
            case "Main":
                if (_player)
                {
                    Destroy(_player);
                    _player = null;
                }
                break;
            case "Stage01":
            case "Stage02":
                var spawnPoint = GameObject.FindGameObjectWithTag("SpawnPoint").transform;
                if (_player)
                {
                    _player.transform.position = spawnPoint.position;
                    _player.transform.rotation = spawnPoint.rotation;
                    _player.SetActive(true);
                }
                else
                {
                    _player = Instantiate(playerPrefab, spawnPoint.position, spawnPoint.rotation);
                    DontDestroyOnLoad(_player);
                }
                break;
        }

        // GameState = EGameState.Play;
        SetGameState(EGameState.Play);
    }

    protected override void OnSceneUnloaded(Scene scene)
    {
        _player.SetActive(false);
    }

    // 캔버스가 존재하지 않을 때 처리
    private Canvas GetCanvas()
    {
        var canvasObject = GameObject.FindGameObjectWithTag("Canvas");
        Canvas result = null; // 리턴용 캔버스

        if (!canvasObject)
        {
            canvasObject = new GameObject("Canvas");
            canvasObject.AddComponent<Canvas>();
            canvasObject.AddComponent<CanvasScaler>();
            canvasObject.AddComponent<GraphicRaycaster>();

            result = canvasObject.GetComponent<Canvas>();
            result.renderMode = RenderMode.ScreenSpaceOverlay;
            result.tag = "Canvas";
        }
        else
        {
            result = canvasObject.GetComponent<Canvas>();
        }

        return result;
    }
}
