using System;
using System.Collections;
using UnityEngine;
using UnityEngine.Networking;
using UnityEngine.SceneManagement;

public class NetworkManager : Singleton<NetworkManager>
{
    // �α���
    public IEnumerator Signin(SigninData signinData, Action success, Action<int> failure)
    {
        string jsonString = JsonUtility.ToJson(signinData); // ����ü ���� json ������ ���ڿ��� �ٲٱ�

        // Post ������� �� ���� -> btye Ÿ���̾�� ��
        byte[] byteRaw = System.Text.Encoding.UTF8.GetBytes(jsonString);

        using (UnityWebRequest www = new UnityWebRequest(Constants.ServerURL + "/users/signin",
            UnityWebRequest.kHttpVerbPOST))
        {
            www.uploadHandler = new UploadHandlerRaw(byteRaw);
            www.downloadHandler = new DownloadHandlerBuffer(); // ���� ���� �޾ƿ���
            www.SetRequestHeader("Content-Type", "application/json"); // Http ���������� header ������ �̷�

            yield return www.SendWebRequest(); // �������� ���� ���� ������ ���

            // ���� ������ �߻����� ���
            if (www.result == UnityWebRequest.Result.ConnectionError)
            {
                // TODO : ���� ���� ������ ���� �˸�
            }
            else
            {
                var resultString = www.downloadHandler.text;
                var result = JsonUtility.FromJson<SigninResult>(resultString); // Json�� ����ü ���·� �ٲٱ�

                if (result.result == 2)
                {
                    success?.Invoke();
                }
                else
                {
                    failure?.Invoke(result.result);
                }
            }
        };
    }

    protected override void OnSceneLoad(Scene scene, LoadSceneMode mode)
    {
        
    }
}
